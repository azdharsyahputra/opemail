package tests

import (
	"bufio"
	"context"
	"crypto/tls"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"


	"github.com/azdharsyahputra/openmail/internal/config"
	"github.com/azdharsyahputra/openmail/internal/database"
	"github.com/azdharsyahputra/openmail/internal/domain"
	"github.com/azdharsyahputra/openmail/internal/dovecot"
	"github.com/azdharsyahputra/openmail/internal/mailbox"
	"github.com/azdharsyahputra/openmail/internal/provisioning"
)

func TestIntegration_Dovecot(t *testing.T) {
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
	if err := database.RunMigrationsUp(db); err != nil {
		t.Fatalf("failed to run migrations up: %v", err)
	}


	tempVmailDir, err := os.MkdirTemp("", "openmail-dovecot-vmail-*")
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

	// 1. Create Domain
	_ = domainSvc.Delete(ctx, "example.com")
	_, err = domainSvc.Create(ctx, "example.com")
	if err != nil {
		t.Fatalf("failed to create domain: %v", err)
	}


	// 2. Create Mailbox with Argon2id password
	mb, err := mailboxSvc.Create(ctx, "ajar@example.com", "SecurePass123", 1073741824)
	if err != nil {
		t.Fatalf("failed to create mailbox: %v", err)
	}

	// 3. Authentication Test Matrix (Item 38)
	t.Run("Auth Matrix: active + ready + correct PW -> PASS", func(t *testing.T) {
		err := dovecotSvc.Authenticate(ctx, "ajar@example.com", "SecurePass123")
		if err != nil {
			t.Errorf("expected authentication success, got %v", err)
		}
	})

	t.Run("Auth Matrix: case-insensitive uppercase -> PASS", func(t *testing.T) {
		err := dovecotSvc.Authenticate(ctx, "AJAR@EXAMPLE.COM", "SecurePass123")
		if err != nil {
			t.Errorf("expected uppercase username auth to succeed, got %v", err)
		}
	})

	t.Run("Auth Matrix: active + ready + wrong PW -> FAIL", func(t *testing.T) {
		err := dovecotSvc.Authenticate(ctx, "ajar@example.com", "WrongPassword")
		if err != dovecot.ErrAuthenticationFailed {
			t.Errorf("expected ErrAuthenticationFailed, got %v", err)
		}
	})

	t.Run("Auth Matrix: unknown user -> FAIL", func(t *testing.T) {
		err := dovecotSvc.Authenticate(ctx, "ghost@example.com", "SecurePass123")
		if err != dovecot.ErrAuthenticationFailed {
			t.Errorf("expected ErrAuthenticationFailed, got %v", err)
		}
	})

	t.Run("Auth Matrix: suspended user + correct PW -> FAIL", func(t *testing.T) {
		_ = mailboxRepo.UpdateStatus(ctx, mb.ID, "suspended")
		err := dovecotSvc.Authenticate(ctx, "ajar@example.com", "SecurePass123")
		if err != dovecot.ErrAuthenticationFailed {
			t.Errorf("expected suspended user to fail authentication, got %v", err)
		}
		_ = mailboxRepo.UpdateStatus(ctx, mb.ID, "active")
	})

	t.Run("Auth Matrix: pending user + correct PW -> FAIL", func(t *testing.T) {
		_ = mailboxRepo.UpdateProvisioningStatus(ctx, mb.ID, mailbox.ProvisioningPending)
		err := dovecotSvc.Authenticate(ctx, "ajar@example.com", "SecurePass123")
		if err != dovecot.ErrAuthenticationFailed {
			t.Errorf("expected pending user to fail authentication, got %v", err)
		}
		_ = mailboxRepo.UpdateProvisioningStatus(ctx, mb.ID, mailbox.ProvisioningReady)
	})

	t.Run("Auth Matrix: deleted user + correct PW -> FAIL", func(t *testing.T) {
		_ = mailboxRepo.UpdateStatus(ctx, mb.ID, "deleted")
		err := dovecotSvc.Authenticate(ctx, "ajar@example.com", "SecurePass123")
		if err != dovecot.ErrAuthenticationFailed {
			t.Errorf("expected deleted user to fail authentication, got %v", err)
		}
		_ = mailboxRepo.UpdateStatus(ctx, mb.ID, "active")
	})

	// 4. Test Userdb Lookup (Derived Maildir Location - Item 10, 11, 12, 13)
	t.Run("Userdb: GetUserInfo returns derived path and uid/gid", func(t *testing.T) {
		info, err := dovecotSvc.GetUserInfo(ctx, "ajar@example.com", tempVmailDir, 5000, 5000)
		if err != nil {
			t.Fatalf("expected userdb lookup success, got %v", err)
		}
		expectedPath := filepath.Join(tempVmailDir, "example.com", "ajar", "Maildir")
		if info.Home != expectedPath {
			t.Errorf("expected home %s, got %s", expectedPath, info.Home)
		}
		if info.UID != 5000 || info.GID != 5000 {
			t.Errorf("expected UID/GID 5000, got %d/%d", info.UID, info.GID)
		}
	})

	// 5. Security Test Matrix (Item 40)
	t.Run("Security Matrix: Dovecot DB role is read-only", func(t *testing.T) {
		dovecotDBURL := "postgres://mailopen_dovecot:dovecot_secret@localhost:5432/postgres?sslmode=disable"
		if strings.Contains(dbURL, "5433") {
			dovecotDBURL = "postgres://mailopen_dovecot:dovecot_secret@localhost:5433/mailopen?sslmode=disable"
		}
		dDB, err := sql.Open("pgx", dovecotDBURL)
		if err != nil {
			t.Skipf("cannot connect with mailopen_dovecot: %v", err)
			return
		}
		defer dDB.Close()

		if err := dDB.Ping(); err != nil {
			t.Skipf("mailopen_dovecot ping failed: %v", err)
			return
		}

		// SELECT must succeed
		var count int
		err = dDB.QueryRow("SELECT count(*) FROM mailboxes").Scan(&count)
		if err != nil {
			t.Errorf("mailopen_dovecot SELECT failed: %v", err)
		}

		// INSERT / UPDATE must fail with permission denied
		_, err = dDB.Exec("UPDATE mailboxes SET status = 'active'")
		if err == nil {
			t.Errorf("expected mailopen_dovecot UPDATE to be rejected with permission denied")
		}
	})

	// 6. Live IMAP Session Matrix (Item 34, 35, 36, 39)
	t.Run("Mailbox Access Matrix: Live IMAPS :993 Session", func(t *testing.T) {
		tlsConn, err := tls.Dial("tcp", "127.0.0.1:993", &tls.Config{InsecureSkipVerify: true})
		if err != nil {
			t.Skip("IMAPS service not running on 127.0.0.1:993, skipping live socket test")
			return
		}
		defer tlsConn.Close()

		reader := bufio.NewReader(tlsConn)
		writer := bufio.NewWriter(tlsConn)


		// Greeting
		greeting, err := reader.ReadString('\n')
		if err != nil || !strings.Contains(greeting, "Dovecot ready") {
			t.Fatalf("unexpected greeting: %s (err: %v)", greeting, err)
		}

		sendCmd := func(tag, cmd string) (string, error) {
			_, err := writer.WriteString(tag + " " + cmd + "\r\n")
			if err != nil {
				return "", err
			}
			if err := writer.Flush(); err != nil {
				return "", err
			}

			var response strings.Builder
			for {
				line, err := reader.ReadString('\n')
				if err != nil {
					return response.String(), err
				}
				response.WriteString(line)
				if strings.HasPrefix(line, tag+" ") {
					break
				}
			}
			return response.String(), nil
		}

		// [x] LOGIN
		resp, err := sendCmd("a1", "LOGIN ajar@example.com SecurePass123")
		if err != nil || !strings.Contains(resp, "a1 OK") {
			t.Fatalf("LOGIN failed: %s (err: %v)", resp, err)
		}

		// [x] SELECT INBOX
		resp, err = sendCmd("a2", "SELECT INBOX")
		if err != nil || !strings.Contains(resp, "a2 OK") {
			t.Fatalf("SELECT INBOX failed: %s (err: %v)", resp, err)
		}

		// [x] STATUS INBOX
		resp, err = sendCmd("a3", "STATUS INBOX (MESSAGES UNSEEN)")
		if err != nil || !strings.Contains(resp, "a3 OK") {
			t.Fatalf("STATUS INBOX failed: %s (err: %v)", resp, err)
		}

		// [x] SEARCH
		resp, err = sendCmd("a4", "SEARCH ALL")
		if err != nil || !strings.Contains(resp, "a4 OK") {
			t.Fatalf("SEARCH failed: %s (err: %v)", resp, err)
		}

		// [x] FETCH headers
		resp, err = sendCmd("a5", "FETCH 1 (BODY.PEEK[HEADER])")
		if err != nil || !strings.Contains(resp, "a5 OK") {
			t.Fatalf("FETCH headers failed: %s (err: %v)", resp, err)
		}

		// [x] FETCH body
		resp, err = sendCmd("a6", "FETCH 1 (BODY.PEEK[TEXT])")
		if err != nil || !strings.Contains(resp, "a6 OK") {
			t.Fatalf("FETCH body failed: %s (err: %v)", resp, err)
		}

		// [x] LOGOUT
		resp, err = sendCmd("a7", "LOGOUT")
		if err != nil || !strings.Contains(resp, "a7 OK") {
			t.Fatalf("LOGOUT failed: %s (err: %v)", resp, err)
		}
	})
}
