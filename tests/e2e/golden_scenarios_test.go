package e2e_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"database/sql"
	"fmt"
	"net"
	"net/smtp"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/azdharsyahputra/openmail/internal/backup"
	"github.com/azdharsyahputra/openmail/internal/config"
	"github.com/azdharsyahputra/openmail/internal/database"
	"github.com/azdharsyahputra/openmail/internal/domain"
	"github.com/azdharsyahputra/openmail/internal/mailbox"
	"github.com/azdharsyahputra/openmail/internal/provisioning"
	"github.com/azdharsyahputra/openmail/internal/queue"
	"github.com/azdharsyahputra/openmail/internal/quota"
	"github.com/azdharsyahputra/openmail/internal/system"
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

func setupE2ETestDB(t *testing.T) (*sql.DB, string) {


	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		cfg, err := config.Load()
		if err == nil && cfg.DatabaseURL != "" {
			dbURL = cfg.DatabaseURL
		} else {
			dbURL = "postgres://mailopen:mailopen@localhost:5433/mailopen?sslmode=disable"
		}
	}

	db, err := database.NewPostgresDB(dbURL)
	if err != nil {
		t.Skipf("Skipping E2E test: PostgreSQL unavailable (%v)", err)
		return nil, ""
	}

	if err := database.RunMigrationsUp(db); err != nil {
		t.Fatalf("failed to run migrations: %v", err)
	}

	testDomain := fmt.Sprintf("golden-%d.example.com", time.Now().UnixNano())
	domRepo := domain.NewPostgresRepository(db)
	_ = domRepo.Create(context.Background(), &domain.Domain{ID: uuid.New(), Name: testDomain, Status: "active"})

	return db, testDomain
}

func TestGolden_10Scenarios(t *testing.T) {
	db, testDomain := setupE2ETestDB(t)
	if db == nil {
		return
	}
	defer db.Close()

	ctx := context.Background()
	cfg, _ := config.Load()
	vmailRoot := cfg.VmailRoot
	if vmailRoot == "" {
		vmailRoot = "./data/vmail"
	}

	domRepo := domain.NewPostgresRepository(db)
	mbRepo := mailbox.NewPostgresRepository(db)
	prov, _ := provisioning.NewFilesystemProvisioner(vmailRoot, 5000, 5000)
	mbSvc := mailbox.NewService(mbRepo, domRepo, prov)
	quotaSvc := quota.NewService(mbRepo, prov)

	userEmail := "golden-user@" + testDomain
	userPass := "GoldenSecurePass2026!"
	_, err := mbSvc.Create(ctx, userEmail, userPass, 1073741824)
	if err != nil {
		t.Fatalf("failed to create golden user: %v", err)
	}
	_, _, err = mbSvc.Provision(ctx, userEmail)
	if err != nil {
		t.Fatalf("failed to provision golden user: %v", err)
	}


	aliasEmail := "support@" + testDomain
	_, err = db.ExecContext(ctx, "INSERT INTO aliases (id, domain_id, source, destination, created_at) VALUES ($1, (SELECT id FROM domains WHERE name = $2), $3, $4, NOW())",
		uuid.New(), testDomain, aliasEmail, userEmail)
	if err != nil {
		t.Fatalf("failed to create alias: %v", err)
	}


	// GOLDEN-001: Inbound Basic (Internet -> Postfix :25 -> Maildir -> Dovecot IMAP :143)
	t.Run("GOLDEN-001: Inbound Basic Flow", func(t *testing.T) {
		conn25, err := net.DialTimeout("tcp", "127.0.0.1:25", 500*time.Millisecond)
		if err != nil {
			t.Skip("Postfix :25 not reachable")
			return
		}
		_ = conn25.Close()

		c, err := dialSMTPWithRetry("127.0.0.1:25")
		if err != nil {
			t.Fatalf("dial 25 failed: %v", err)
		}
		defer c.Close()

		_ = c.Hello("mx.google.com")
		_ = c.StartTLS(&tls.Config{InsecureSkipVerify: true})
		if err := c.Mail("external-sender@google.com"); err != nil {
			t.Fatalf("MAIL FROM failed: %v", err)
		}
		if err := c.Rcpt(userEmail); err != nil {
			t.Fatalf("RCPT TO failed: %v", err)
		}
		w, err := c.Data()
		if err != nil {
			t.Fatalf("DATA failed: %v", err)
		}
		msgID := fmt.Sprintf("<golden-001-%d@google.com>", time.Now().UnixNano())
		_, _ = fmt.Fprintf(w, "From: external-sender@google.com\r\nTo: %s\r\nSubject: GOLDEN-001 Test\r\nMessage-ID: %s\r\n\r\nGolden scenario 1 content\r\n", userEmail, msgID)
		_ = w.Close()

		// Allow delivery to reach disk
		time.Sleep(300 * time.Millisecond)

		// Verify user can read via IMAP
		conn143, err := net.DialTimeout("tcp", "127.0.0.1:143", 500*time.Millisecond)
		if err != nil {
			t.Skip("Dovecot :143 not reachable")
			return
		}
		defer conn143.Close()

		r := bufio.NewReader(conn143)
		_, _ = r.ReadString('\n')
		fmt.Fprintf(conn143, "G001 STARTTLS\r\n")
		_, _ = r.ReadString('\n')

		tlsConn := tls.Client(conn143, &tls.Config{InsecureSkipVerify: true})
		_ = tlsConn.Handshake()
		tlsR := bufio.NewReader(tlsConn)

		fmt.Fprintf(tlsConn, "G002 LOGIN %s %s\r\n", userEmail, userPass)
		loginResp, _ := tlsR.ReadString('\n')
		if !strings.HasPrefix(loginResp, "G002 OK") {
			t.Fatalf("IMAP login failed: %s", loginResp)
		}

		fmt.Fprintf(tlsConn, "G003 SELECT INBOX\r\n")
		for {
			line, err := tlsR.ReadString('\n')
			if err != nil || strings.HasPrefix(line, "G003 OK") {
				break
			}
		}

		fmt.Fprintf(tlsConn, "G004 LOGOUT\r\n")
		_, _ = tlsR.ReadString('\n')
	})

	// GOLDEN-002: Outbound Basic (Submission :587 -> STARTTLS -> AUTH -> Sender Auth -> Postfix)
	t.Run("GOLDEN-002: Outbound Submission & Auth", func(t *testing.T) {
		conn587, err := net.DialTimeout("tcp", "127.0.0.1:587", 500*time.Millisecond)
		if err != nil {
			t.Skip("Submission :587 not reachable")
			return
		}
		_ = conn587.Close()

		c, err := dialSMTPWithRetry("127.0.0.1:587")

		if err != nil {
			t.Fatalf("dial 587 failed: %v", err)
		}
		defer c.Close()

		if err := c.StartTLS(&tls.Config{InsecureSkipVerify: true}); err != nil {
			t.Fatalf("STARTTLS on 587 failed: %v", err)
		}

		auth := &plainAuthNoSecurityCheck{"", userEmail, userPass}
		if err := c.Auth(auth); err != nil {
			t.Fatalf("AUTH on 587 failed: %v", err)
		}

		if err := c.Mail(userEmail); err != nil {
			t.Fatalf("MAIL FROM failed: %v", err)
		}
		if err := c.Rcpt("outbound-target@gmail.com"); err != nil {
			t.Fatalf("RCPT TO outbound failed: %v", err)
		}

		w, err := c.Data()
		if err != nil {
			t.Fatalf("DATA failed: %v", err)
		}
		_, _ = fmt.Fprintf(w, "From: %s\r\nTo: outbound-target@gmail.com\r\nSubject: GOLDEN-002 Outbound\r\n\r\nOutbound body payload\r\n", userEmail)
		_ = w.Close()
	})

	// GOLDEN-003: Alias Delivery (support@ -> golden-user@)
	t.Run("GOLDEN-003: Alias Delivery", func(t *testing.T) {
		conn25, err := net.DialTimeout("tcp", "127.0.0.1:25", 500*time.Millisecond)
		if err != nil {
			t.Skip("Postfix :25 not reachable")
			return
		}
		_ = conn25.Close()

		c, err := dialSMTPWithRetry("127.0.0.1:25")
		if err != nil {
			t.Fatalf("dial 25 failed: %v", err)
		}
		defer c.Close()

		_ = c.Hello("client.test.com")
		_ = c.StartTLS(&tls.Config{InsecureSkipVerify: true})
		_ = c.Mail("customer@example.com")
		if err := c.Rcpt(aliasEmail); err != nil {
			t.Fatalf("expected alias recipient to be accepted, got: %v", err)
		}
		w, _ := c.Data()
		if w != nil {
			_, _ = fmt.Fprintf(w, "Subject: Help Request via Alias\r\n\r\nSupport ticket\r\n")
			_ = w.Close()
		}
	})

	// GOLDEN-004: Invalid Recipient (ghost@ -> 550 without creating Maildir)
	t.Run("GOLDEN-004: Invalid Recipient Rejection", func(t *testing.T) {
		conn25, err := net.DialTimeout("tcp", "127.0.0.1:25", 500*time.Millisecond)
		if err != nil {
			t.Skip("Postfix :25 not reachable")
			return
		}
		_ = conn25.Close()

		c, err := dialSMTPWithRetry("127.0.0.1:25")
		if err != nil {
			t.Fatalf("dial 25 failed: %v", err)
		}
		defer c.Close()

		_ = c.Hello("client.test.com")
		_ = c.StartTLS(&tls.Config{InsecureSkipVerify: true})
		_ = c.Mail("sender@test.com")
		err = c.Rcpt("ghost@" + testDomain)
		if err == nil {
			t.Errorf("expected ghost recipient to be rejected with 550")
		}

		ghostPath, _ := prov.CalculatePath("ghost@" + testDomain)
		if _, err := os.Stat(ghostPath); !os.IsNotExist(err) {
			t.Errorf("expected ghost Maildir to NOT be created on disk")
		}
	})

	// GOLDEN-008: Quota Rejection (552 5.2.2 Mailbox is full)
	t.Run("GOLDEN-008: Quota Exceeded Rejection", func(t *testing.T) {
		fullUser := "full-inbox@" + testDomain
		_, _ = mbSvc.Create(ctx, fullUser, "Pass123!", 500) // 500 bytes quota

		// Try incoming 1000 bytes
		canAccept, err := quotaSvc.CheckCanAccept(ctx, fullUser, 1000)
		if canAccept || err != quota.ErrQuotaExceeded {
			t.Errorf("expected quota rejection ErrQuotaExceeded, got: %t (%v)", canAccept, err)
		}
	})

	// GOLDEN-009: Dynamic Password Rotation without Service Restart
	t.Run("GOLDEN-009: Dynamic Password Rotation", func(t *testing.T) {
		rotUser := "rot-user@" + testDomain
		oldPass := "OldSecret123!"
		newPass := "NewSecret456!"
		_, _ = mbSvc.Create(ctx, rotUser, oldPass, 1073741824)

		// Authenticate with old password -> PASS
		_, err := mbSvc.Authenticate(ctx, rotUser, oldPass)
		if err != nil {
			t.Fatalf("old pass auth failed: %v", err)
		}

		// Update password
		err = mbSvc.SetPassword(ctx, rotUser, newPass)
		if err != nil {
			t.Fatalf("set password failed: %v", err)
		}

		// Old password -> FAIL
		_, err = mbSvc.Authenticate(ctx, rotUser, oldPass)
		if err == nil {
			t.Errorf("expected old password to fail after rotation")
		}

		// New password -> PASS
		_, err = mbSvc.Authenticate(ctx, rotUser, newPass)
		if err != nil {
			t.Errorf("expected new password to succeed: %v", err)
		}
	})

	// GOLDEN-010: Disaster Recovery Boss Fight (Destroy & Restore -> System Doctor HEALTHY)
	t.Run("GOLDEN-010: Disaster Recovery Boss Fight", func(t *testing.T) {
		tempDir := t.TempDir()
		backupFile := filepath.Join(tempDir, "dr-backup.tar.gz.enc")
		restoreDir := filepath.Join(tempDir, "restored")
		passphrase := "BossFightPass2026!"

		bCfg := backup.BackupConfig{
			DB:         db,
			VmailDir:   vmailRoot,
			DKIMDir:    cfg.DKIMBaseDir,
			TLSDir:     cfg.TLSBaseDir,
			ConfigDir:  cfg.PostfixConfigDir,
			Passphrase: passphrase,
			OutputPath: backupFile,
		}

		manifest, _, err := backup.CreateBackup(ctx, bCfg)
		if err != nil {
			t.Fatalf("disaster backup create failed: %v", err)
		}
		if !manifest.Encrypted {
			t.Errorf("expected encrypted backup manifest")
		}

		// Verify & Restore into fresh directory
		vReport, err := backup.VerifyBackup(backupFile, passphrase)
		if err != nil || !vReport.Valid {
			t.Fatalf("backup verification failed: %v", err)
		}

		res, err := backup.RestoreBackup(ctx, backupFile, passphrase, restoreDir)
		if err != nil {
			t.Fatalf("backup restore failed: %v", err)
		}
		if res.FilesRestored == 0 {
			t.Errorf("expected restored files, got 0")
		}

		// Run System Doctor across restored files
		qSvc := queue.NewService(queue.NewSystemDriver("mailopen_postfix"))
		report := system.RunSystemDoctor(ctx, system.SystemDoctorDeps{
			DB:           db,
			QueueService: qSvc,
			VmailDir:     restoreDir,
			TLSPath:      cfg.TLSBaseDir,
			DKIMPath:     cfg.DKIMBaseDir,
		})

		if !report.Healthy {
			t.Errorf("expected disaster recovery doctor to be HEALTHY, got false")
		}
	})
}
