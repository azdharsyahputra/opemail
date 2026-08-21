package tests

import (
	"context"
	"crypto/tls"
	"net"
	"net/smtp"
	"os"

	"testing"
	"time"

	"github.com/azdharsyahputra/openmail/internal/config"

	"github.com/azdharsyahputra/openmail/internal/database"
	"github.com/azdharsyahputra/openmail/internal/domain"
	"github.com/azdharsyahputra/openmail/internal/dovecot"
	"github.com/azdharsyahputra/openmail/internal/mailbox"
	"github.com/azdharsyahputra/openmail/internal/postfix"
	"github.com/azdharsyahputra/openmail/internal/provisioning"
)

type plainAuthNoTLS struct {
	username, password string
}

func (a *plainAuthNoTLS) Start(server *smtp.ServerInfo) (string, []byte, error) {
	return "PLAIN", []byte("\x00" + a.username + "\x00" + a.password), nil
}

func (a *plainAuthNoTLS) Next(fromServer []byte, more bool) ([]byte, error) {
	return nil, nil
}

func TestIntegration_Submission(t *testing.T) {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		cfg, err := config.Load()
		if err == nil && cfg.DatabaseURL != "" {
			dbURL = cfg.DatabaseURL
		} else {
			dbURL = "postgres://mailopen:mailopen@localhost:5432/mailopen?sslmode=disable"
		}
	}

	db, err := database.NewPostgresDB(dbURL)
	if err != nil {
		t.Skipf("Skipping integration test: PostgreSQL unavailable (%v)", err)
		return
	}
	defer db.Close()

	if err := database.RunMigrationsUp(db); err != nil {
		t.Fatalf("failed to run migrations up: %v", err)
	}



	tempVmailDir, err := os.MkdirTemp("", "openmail-submission-vmail-*")
	if err != nil {
		t.Fatalf("failed to create temp vmail directory: %v", err)
	}
	defer os.RemoveAll(tempVmailDir)

	prov, err := provisioning.NewFilesystemProvisioner(tempVmailDir, 0, 0)
	if err != nil {
		t.Fatalf("failed to create provisioner: %v", err)
	}

	ctx := context.Background()
	domainRepo := domain.NewPostgresRepository(db)
	mailboxRepo := mailbox.NewPostgresRepository(db)
	dovecotRepo := dovecot.NewPostgresRepository(db)

	domainSvc := domain.NewService(domainRepo)
	mailboxSvc := mailbox.NewService(mailboxRepo, domainRepo, prov)
	dovecotSvc := dovecot.NewService(dovecotRepo, dovecot.NewSystemProvisioner("/tmp"))
	senderAuthorizer := postfix.NewPostgresSenderAuthorizer(db)

	// 1. Create Domain
	_ = domainSvc.Delete(ctx, "example.com")
	dom, err := domainSvc.Create(ctx, "example.com")
	if err != nil {
		t.Fatalf("failed to create domain: %v", err)
	}


	// 2. Create Mailbox with Argon2id password
	mb, err := mailboxSvc.Create(ctx, "ajar@example.com", "SecurePass123", 1073741824)
	if err != nil {
		t.Fatalf("failed to create mailbox: %v", err)
	}

	// 3. Create Alias support@example.com -> ajar@example.com
	_, err = db.ExecContext(ctx, `
		INSERT INTO aliases (id, domain_id, source, destination, created_at)
		VALUES (gen_random_uuid(), $1, 'support@example.com', 'ajar@example.com', NOW());
	`, dom.ID)
	if err != nil {
		t.Fatalf("failed to insert alias: %v", err)
	}


	// 4. Test Sender Authorization Matrix
	t.Run("SenderAuth: Primary mailbox address -> PASS", func(t *testing.T) {
		canSend, err := senderAuthorizer.CanSendAs(ctx, "ajar@example.com", "ajar@example.com")
		if err != nil || !canSend {
			t.Errorf("expected primary address authorized, got canSend=%v err=%v", canSend, err)
		}
	})

	t.Run("SenderAuth: Authorized alias -> PASS", func(t *testing.T) {
		canSend, err := senderAuthorizer.CanSendAs(ctx, "ajar@example.com", "support@example.com")
		if err != nil || !canSend {
			t.Errorf("expected alias authorized, got canSend=%v err=%v", canSend, err)
		}
	})

	t.Run("SenderAuth: Unauthorized spoofed sender -> FAIL", func(t *testing.T) {
		canSend, err := senderAuthorizer.CanSendAs(ctx, "ajar@example.com", "ceo@bank.com")
		if err != nil || canSend {
			t.Errorf("expected spoofed sender to fail authorization, got canSend=%v", canSend)
		}
	})

	// 5. Test Live Submission (:587) if reachable
	t.Run("Live Submission :587 and SMTP AUTH Matrix", func(t *testing.T) {
		conn, err := net.DialTimeout("tcp", "127.0.0.1:587", 500*time.Millisecond)
		if err != nil {
			t.Skip("Submission port :587 not listening on localhost, skipping live socket test")
			return
		}
		_ = conn.Close()

		// A. Authenticated Submission with correct password -> PASS
		c, err := smtp.Dial("127.0.0.1:587")
		if err != nil {
			t.Fatalf("failed to connect to :587: %v", err)
		}
		defer c.Close()

		_ = c.StartTLS(&tls.Config{InsecureSkipVerify: true})

		auth := &plainAuthNoTLS{username: "ajar@example.com", password: "SecurePass123"}
		if err := c.Auth(auth); err != nil {
			t.Fatalf("expected AUTH to succeed: %v", err)
		}

		if err := c.Mail("ajar@example.com"); err != nil {
			t.Fatalf("expected MAIL FROM to succeed: %v", err)
		}
		if err := c.Rcpt("recipient@example.net"); err != nil {
			t.Fatalf("expected RCPT TO to succeed: %v", err)
		}
		w, err := c.Data()
		if err != nil {
			t.Fatalf("expected DATA to succeed: %v", err)
		}
		_, _ = w.Write([]byte("Subject: W2.6 Test\r\n\r\nBody\r\n"))
		if err := w.Close(); err != nil {
			t.Fatalf("expected DATA close to succeed: %v", err)
		}
		_ = c.Quit()

		// B. Wrong password -> FAIL
		cWrong, err := smtp.Dial("127.0.0.1:587")
		if err == nil {
			defer cWrong.Close()
			_ = cWrong.StartTLS(&tls.Config{InsecureSkipVerify: true})
			authWrong := &plainAuthNoTLS{username: "ajar@example.com", password: "WrongPassword"}
			if err := cWrong.Auth(authWrong); err == nil {
				t.Errorf("expected wrong password to fail AUTH")
			}
		}


		// C. Unauthenticated relay -> FAIL
		cUnauth, err := smtp.Dial("127.0.0.1:587")
		if err == nil {
			defer cUnauth.Close()
			_ = cUnauth.Mail("attacker@evil.com")
			err = cUnauth.Rcpt("someone@gmail.com")
			if err == nil {
				t.Errorf("expected unauthenticated relay to be rejected on :587")
			}
		}
	})

	// 6. Dynamic Password Change without reload
	t.Run("Dynamic Password Change test", func(t *testing.T) {
		// Verify initial auth
		if err := dovecotSvc.Authenticate(ctx, "ajar@example.com", "SecurePass123"); err != nil {
			t.Errorf("initial auth failed: %v", err)
		}

		// Change password via Mailbox service
		if err := mailboxSvc.SetPassword(ctx, "ajar@example.com", "NewPassword456"); err != nil {
			t.Fatalf("failed to update password: %v", err)
		}

		// Old password fails
		if err := dovecotSvc.Authenticate(ctx, "ajar@example.com", "SecurePass123"); err == nil {
			t.Errorf("expected old password to fail after update")
		}

		// New password succeeds
		if err := dovecotSvc.Authenticate(ctx, "ajar@example.com", "NewPassword456"); err != nil {
			t.Errorf("expected new password to succeed: %v", err)
		}
	})

	// 7. Status Suspended and Pending checks
	t.Run("Suspended and Pending accounts fail auth", func(t *testing.T) {
		_ = mailboxRepo.UpdateStatus(ctx, mb.ID, "suspended")
		if err := dovecotSvc.Authenticate(ctx, "ajar@example.com", "NewPassword456"); err != dovecot.ErrAuthenticationFailed {
			t.Errorf("expected suspended user to fail auth")
		}
		_ = mailboxRepo.UpdateStatus(ctx, mb.ID, "active")

		_ = mailboxRepo.UpdateProvisioningStatus(ctx, mb.ID, mailbox.ProvisioningPending)
		if err := dovecotSvc.Authenticate(ctx, "ajar@example.com", "NewPassword456"); err != dovecot.ErrAuthenticationFailed {
			t.Errorf("expected pending user to fail auth")
		}
		_ = mailboxRepo.UpdateProvisioningStatus(ctx, mb.ID, mailbox.ProvisioningReady)
	})
}
