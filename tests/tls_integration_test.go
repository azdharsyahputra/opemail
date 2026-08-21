package tests

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"os"
	"strings"
	"testing"
	"time"


	"github.com/azdharsyahputra/openmail/internal/config"
	"github.com/azdharsyahputra/openmail/internal/database"
	"github.com/azdharsyahputra/openmail/internal/domain"
	"github.com/azdharsyahputra/openmail/internal/mailbox"
	"github.com/azdharsyahputra/openmail/internal/provisioning"
	openmailtls "github.com/azdharsyahputra/openmail/internal/tls"
	"github.com/google/uuid"
)

func dialSMTPWithRetry(addr string) (*smtp.Client, error) {
	var c *smtp.Client
	var err error
	for i := 0; i < 5; i++ {
		c, err = smtp.Dial(addr)
		if err == nil {
			return c, nil
		}
		time.Sleep(150 * time.Millisecond)
	}
	return nil, err
}




func TestIntegration_TLS(t *testing.T) {
	// 1. Check live TLS availability on host
	conn993, err := net.DialTimeout("tcp", "127.0.0.1:993", 500*time.Millisecond)
	if err != nil {
		t.Skip("IMAPS port :993 not reachable on localhost, skipping live socket TLS tests")
		return
	}
	_ = conn993.Close()

	dbURL := os.Getenv("DATABASE_URL")

	if dbURL == "" {
		cfg, err := config.Load()
		if err == nil && cfg.DatabaseURL != "" {
			dbURL = cfg.DatabaseURL
		} else {
			dbURL = "postgres://mailopen:mailopen@localhost:5433/mailopen?sslmode=disable"
		}
	}

	if db, err := database.NewPostgresDB(dbURL); err == nil {
		defer db.Close()
		_ = database.RunMigrationsUp(db)
		domainRepo := domain.NewPostgresRepository(db)
		mailboxRepo := mailbox.NewPostgresRepository(db)
		prov, _ := provisioning.NewFilesystemProvisioner(os.TempDir(), 5000, 5000)
		mbSvc := mailbox.NewService(mailboxRepo, domainRepo, prov)
		ctx := context.Background()
		_ = domainRepo.Create(ctx, &domain.Domain{ID: uuid.New(), Name: "example.com", Status: "active"})
		_ = mbSvc.SetPassword(ctx, "ajar@example.com", "SecurePass123")
		_, _ = mbSvc.Create(ctx, "ajar@example.com", "SecurePass123", 1073741824)
		_, _ = mbSvc.Create(ctx, "bob@example.com", "SecurePass123", 1073741824)
	}

	insecureTLS := &tls.Config{
		InsecureSkipVerify: true,
	}


	// 2. Test TLS Protocol Versions on IMAPS (:993)
	t.Run("TLS Matrix: TLS 1.2 Handshake -> PASS", func(t *testing.T) {
		cfg := insecureTLS.Clone()
		cfg.MinVersion = tls.VersionTLS12
		cfg.MaxVersion = tls.VersionTLS12
		conn, err := tls.Dial("tcp", "127.0.0.1:993", cfg)
		if err != nil {
			t.Fatalf("expected TLS 1.2 to succeed: %v", err)
		}
		defer conn.Close()
		if conn.ConnectionState().Version != tls.VersionTLS12 {
			t.Errorf("expected negotiated version TLS 1.2, got 0x%04x", conn.ConnectionState().Version)
		}
	})

	t.Run("TLS Matrix: TLS 1.3 Handshake -> PASS", func(t *testing.T) {
		cfg := insecureTLS.Clone()
		cfg.MinVersion = tls.VersionTLS13
		cfg.MaxVersion = tls.VersionTLS13
		conn, err := tls.Dial("tcp", "127.0.0.1:993", cfg)
		if err != nil {
			t.Fatalf("expected TLS 1.3 to succeed: %v", err)
		}
		defer conn.Close()
		if conn.ConnectionState().Version != tls.VersionTLS13 {
			t.Errorf("expected negotiated version TLS 1.3, got 0x%04x", conn.ConnectionState().Version)
		}
	})

	t.Run("TLS Matrix: Legacy TLS 1.0 -> BLOCKED", func(t *testing.T) {
		cfg := insecureTLS.Clone()
		cfg.MinVersion = tls.VersionTLS10
		cfg.MaxVersion = tls.VersionTLS10
		conn, err := tls.Dial("tcp", "127.0.0.1:993", cfg)
		if err == nil {
			_ = conn.Close()
			t.Errorf("expected legacy TLS 1.0 to be blocked by Dovecot ssl_min_protocol")
		}
	})

	t.Run("TLS Matrix: Legacy TLS 1.1 -> BLOCKED", func(t *testing.T) {
		cfg := insecureTLS.Clone()
		cfg.MinVersion = tls.VersionTLS11
		cfg.MaxVersion = tls.VersionTLS11
		conn, err := tls.Dial("tcp", "127.0.0.1:993", cfg)
		if err == nil {
			_ = conn.Close()
			t.Errorf("expected legacy TLS 1.1 to be blocked by Dovecot ssl_min_protocol")
		}
	})

	// 3. Test Postfix Submission :587 STARTTLS & Auth Enforcement
	t.Run("Submission :587: Plaintext AUTH before STARTTLS -> BLOCKED", func(t *testing.T) {
		c, err := dialSMTPWithRetry("127.0.0.1:587")
		if err != nil {
			t.Fatalf("connect :587 failed: %v", err)
		}
		defer c.Close()

		auth := &plainAuthNoTLS{username: "ajar@example.com", password: "SecurePass123"}
		err = c.Auth(auth)
		if err == nil {
			t.Errorf("expected AUTH before STARTTLS to fail on :587")
		}
	})

	t.Run("Submission :587: STARTTLS -> AUTH -> Mail Submit -> PASS", func(t *testing.T) {
		c, err := dialSMTPWithRetry("127.0.0.1:587")
		if err != nil {
			t.Fatalf("connect :587 failed: %v", err)
		}
		defer c.Close()


		if err := c.StartTLS(insecureTLS); err != nil {
			t.Fatalf("STARTTLS failed on :587: %v", err)
		}

		auth := &plainAuthNoTLS{username: "ajar@example.com", password: "SecurePass123"}
		if err := c.Auth(auth); err != nil {
			t.Fatalf("AUTH after STARTTLS failed: %v", err)
		}

		if err := c.Mail("ajar@example.com"); err != nil {
			t.Fatalf("MAIL FROM failed: %v", err)
		}
		if err := c.Rcpt("bob@example.com"); err != nil {
			t.Fatalf("RCPT TO failed: %v", err)
		}
		w, err := c.Data()
		if err != nil {
			t.Fatalf("DATA failed: %v", err)
		}
		_, _ = fmt.Fprintf(w, "Subject: W2.7 Integration Test\r\n\r\nEncrypted Payload\r\n")
		if err := w.Close(); err != nil {
			t.Fatalf("DATA close failed: %v", err)
		}
		_ = c.Quit()
	})

	// 4. Test Port 25: STARTTLS Offered, AUTH Disabled
	t.Run("Inbound :25: STARTTLS offered, AUTH disabled", func(t *testing.T) {
		c, err := smtp.Dial("127.0.0.1:25")
		if err != nil {
			t.Skipf("Port 25 not reachable: %v", err)
			return
		}
		defer c.Close()

		if ok, _ := c.Extension("STARTTLS"); !ok {
			t.Errorf("expected port 25 to offer STARTTLS capability")
		}

		// SMTP AUTH should NOT be advertised on port 25
		if ok, _ := c.Extension("AUTH"); ok {
			t.Errorf("port 25 must NOT advertise SMTP AUTH")
		}
	})

	// 5. Test Dovecot IMAP :143 & IMAPS :993
	t.Run("IMAP :143: Plaintext LOGIN before STARTTLS -> BLOCKED", func(t *testing.T) {
		conn, err := net.Dial("tcp", "127.0.0.1:143")
		if err != nil {
			t.Fatalf("connect :143 failed: %v", err)
		}
		defer conn.Close()

		buf := make([]byte, 1024)
		_, _ = conn.Read(buf) // Greeting

		_, _ = conn.Write([]byte("a1 LOGIN ajar@example.com SecurePass123\r\n"))
		n, _ := conn.Read(buf)
		resp := string(buf[:n])

		if strings.Contains(resp, "a1 OK") || !strings.Contains(resp, "NO") {
			t.Errorf("expected plaintext login on :143 to be rejected with NO/PRIVACYREQUIRED, got: %s", resp)
		}
	})

	t.Run("IMAP :993: Implicit TLS session -> LOGIN -> PASS", func(t *testing.T) {
		conn, err := tls.Dial("tcp", "127.0.0.1:993", insecureTLS)
		if err != nil {
			t.Fatalf("IMAPS connect failed: %v", err)
		}
		defer conn.Close()

		buf := make([]byte, 1024)
		_, _ = conn.Read(buf) // Greeting

		_, _ = conn.Write([]byte("a1 LOGIN ajar@example.com SecurePass123\r\n"))
		n, _ := conn.Read(buf)
		resp := string(buf[:n])

		if !strings.Contains(resp, "a1 OK") {
			t.Errorf("expected IMAPS login to succeed, got: %s", resp)
		}
		_, _ = conn.Write([]byte("a2 LOGOUT\r\n"))
	})

	// 6. Test Doctor Verification
	t.Run("Doctor: Verify TLS Health Report", func(t *testing.T) {
		tlsDir := "../data/tls"
		if _, err := os.Stat(tlsDir); err != nil {
			tlsDir = "./data/tls"
		}
		postfixDir := "../data/postfix"
		if _, err := os.Stat(postfixDir); err != nil {
			postfixDir = "./data/postfix"
		}
		dovecotDir := "../data/dovecot"
		if _, err := os.Stat(dovecotDir); err != nil {
			dovecotDir = "./data/dovecot"
		}

		provider := openmailtls.NewFilesystemProvider(tlsDir)
		report := openmailtls.RunDoctor(context.Background(), provider, "mail.example.com", postfixDir, dovecotDir)
		if !report.Healthy {
			for _, c := range report.Checks {
				if !c.Passed {
					t.Logf("Failed check: %s / %s -> %s", c.Category, c.Name, c.Message)
				}
			}
			t.Errorf("expected Doctor report to be HEALTHY")
		}
	})
}
