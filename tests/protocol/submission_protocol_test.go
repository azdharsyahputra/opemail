package protocol_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"strings"
	"testing"
	"time"

	"github.com/azdharsyahputra/openmail/internal/domain"
	"github.com/azdharsyahputra/openmail/internal/mailbox"
	"github.com/azdharsyahputra/openmail/internal/provisioning"
	"github.com/google/uuid"
)

type plainAuthNoSecurityCheck struct {

	identity, username, password string
}

func (a *plainAuthNoSecurityCheck) Start(server *smtp.ServerInfo) (string, []byte, error) {
	resp := []byte(a.identity + "\x00" + a.username + "\x00" + a.password)
	return "PLAIN", resp, nil
}

func (a *plainAuthNoSecurityCheck) Next(fromServer []byte, more bool) ([]byte, error) {
	return nil, nil
}

func dialSubmissionWithRetry(addr string) (*smtp.Client, error) {

	var c *smtp.Client
	var err error
	for i := 0; i < 5; i++ {
		c, err = smtp.Dial(addr)
		if err == nil {
			return c, nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return nil, err
}

func TestSubmission_ProtocolCompliance(t *testing.T) {
	conn587, err := net.DialTimeout("tcp", "127.0.0.1:587", 500*time.Millisecond)
	if err != nil {
		t.Skip("SMTP Submission port :587 not reachable, skipping live submission test")
		return
	}
	_ = conn587.Close()

	db, testDomain := setupProtocolTestDB(t)
	if db == nil {
		return
	}
	defer db.Close()

	ctx := context.Background()
	domRepo := domain.NewPostgresRepository(db)
	mbRepo := mailbox.NewPostgresRepository(db)
	prov, _ := provisioning.NewFilesystemProvisioner(t.TempDir(), 5000, 5000)
	mbSvc := mailbox.NewService(mbRepo, domRepo, prov)

	userEmail := "sub-user@" + testDomain
	password := "SubmissionSecret2026!"
	_, err = mbSvc.Create(ctx, userEmail, password, 1073741824)
	if err != nil {
		t.Fatalf("failed to create submission user: %v", err)
	}
	_, _, err = mbSvc.Provision(ctx, userEmail)
	if err != nil {
		t.Fatalf("failed to provision mailbox: %v", err)
	}

	// Add alias: support@testDomain -> sub-user@testDomain
	aliasEmail := "support@" + testDomain
	_, err = db.ExecContext(ctx, "INSERT INTO aliases (id, domain_id, source, destination, created_at) VALUES ($1, (SELECT id FROM domains WHERE name = $2), $3, $4, NOW())",
		uuid.New(), testDomain, aliasEmail, userEmail)
	if err != nil {
		t.Fatalf("failed to insert alias: %v", err)
	}

	// SUB-001 & PROTO-002: AUTH before STARTTLS must be blocked (530 Must issue STARTTLS)
	t.Run("SUB-001: AUTH before STARTTLS Prohibited", func(t *testing.T) {
		time.Sleep(100 * time.Millisecond)
		conn, err := net.Dial("tcp", "127.0.0.1:587")
		if err != nil {
			t.Fatalf("dial 587 failed: %v", err)
		}
		defer conn.Close()

		reader := bufio.NewReader(conn)
		_, _ = reader.ReadString('\n')

		fmt.Fprintf(conn, "EHLO client.test.com\r\n")
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				t.Fatalf("read error: %v", err)
			}
			if len(line) >= 4 && line[3] == ' ' {
				break
			}
		}

		// Attempt AUTH PLAIN without STARTTLS
		fmt.Fprintf(conn, "AUTH PLAIN dGVzdAB0ZXN0AHBhc3M=\r\n")
		authResp, _ := reader.ReadString('\n')
		if !strings.HasPrefix(authResp, "530") && !strings.HasPrefix(authResp, "538") && !strings.HasPrefix(authResp, "503") {
			t.Errorf("expected 530 Must issue STARTTLS before AUTH, got: %s", authResp)
		}
	})

	// SUB-002 & SUB-003 & SUB-007: STARTTLS -> AUTH -> Outbound relay allowed
	t.Run("SUB-002 & SUB-003: STARTTLS & Successful Auth", func(t *testing.T) {
		time.Sleep(100 * time.Millisecond)
		c, err := dialSubmissionWithRetry("127.0.0.1:587")
		if err != nil {
			t.Fatalf("smtp dial 587 failed: %v", err)
		}
		defer c.Close()

		if err := c.StartTLS(&tls.Config{InsecureSkipVerify: true}); err != nil {
			t.Fatalf("STARTTLS failed on 587: %v", err)
		}

		auth := &plainAuthNoSecurityCheck{"", userEmail, password}
		if err := c.Auth(auth); err != nil {
			t.Fatalf("AUTH failed: %v", err)
		}

		if err := c.Mail(userEmail); err != nil {
			t.Fatalf("authenticated MAIL FROM failed: %v", err)
		}
		if err := c.Rcpt("external-client@gmail.com"); err != nil {
			t.Fatalf("authenticated relay RCPT TO failed: %v", err)
		}

		w, err := c.Data()
		if err != nil {
			t.Fatalf("DATA command failed: %v", err)
		}
		_, _ = fmt.Fprintf(w, "Subject: Submission Success\r\n\r\nLive submission payload\r\n")
		_ = w.Close()
	})

	// SUB-004: Invalid password -> 535
	t.Run("SUB-004: Invalid password rejected", func(t *testing.T) {
		time.Sleep(100 * time.Millisecond)
		c, err := dialSubmissionWithRetry("127.0.0.1:587")
		if err != nil {
			t.Fatalf("smtp dial 587 failed: %v", err)
		}
		defer c.Close()

		_ = c.StartTLS(&tls.Config{InsecureSkipVerify: true})
		auth := &plainAuthNoSecurityCheck{"", userEmail, "WrongPassword!"}
		err = c.Auth(auth)
		if err == nil {
			t.Errorf("expected wrong password to fail authentication")
		}
	})

	// SUB-009: Sender spoofing rejected (AUTH user tries to send as ceo@testDomain)
	t.Run("SUB-009: Sender spoofing rejected", func(t *testing.T) {
		time.Sleep(100 * time.Millisecond)
		c, err := dialSubmissionWithRetry("127.0.0.1:587")
		if err != nil {
			t.Fatalf("smtp dial 587 failed: %v", err)
		}
		defer c.Close()

		_ = c.StartTLS(&tls.Config{InsecureSkipVerify: true})
		auth := &plainAuthNoSecurityCheck{"", userEmail, password}
		_ = c.Auth(auth)

		errMail := c.Mail("ceo@" + testDomain)
		var errRcpt error
		if errMail == nil {
			errRcpt = c.Rcpt("external-dest@example.com")
		}

		if errMail == nil && errRcpt == nil {
			t.Errorf("expected spoofed sender to be rejected by sender_login_mismatch")
		}
	})

	// SUB-010: Authorized alias accepted (AUTH user sends as support@testDomain)
	t.Run("SUB-010: Authorized alias sender accepted", func(t *testing.T) {
		time.Sleep(100 * time.Millisecond)
		c, err := dialSubmissionWithRetry("127.0.0.1:587")
		if err != nil {
			t.Fatalf("smtp dial 587 failed: %v", err)
		}
		defer c.Close()

		_ = c.StartTLS(&tls.Config{InsecureSkipVerify: true})
		auth := &plainAuthNoSecurityCheck{"", userEmail, password}
		_ = c.Auth(auth)

		err = c.Mail(aliasEmail)
		if err != nil {
			t.Fatalf("expected authorized alias sender to be accepted, got: %v", err)
		}
		_ = c.Rcpt(userEmail)
		w, _ := c.Data()
		if w != nil {
			_, _ = fmt.Fprintf(w, "Subject: Alias Sent\r\n\r\nSent via alias\r\n")
			_ = w.Close()
		}
	})
}
