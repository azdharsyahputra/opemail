package tests

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
	defer db.Close()

	_ = database.DropAllTables(db)

	if err := database.RunMigrationsUp(db); err != nil {
		t.Fatalf("failed to run migrations up: %v", err)
	}
	defer database.DropAllTables(db)


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
	_, err = domainSvc.Create(ctx, "example.com")
	if err != nil {
		t.Fatalf("failed to create domain: %v", err)
	}

	// 2. Create Mailbox with Argon2id password
	mb, err := mailboxSvc.Create(ctx, "ajar@example.com", "SecurePass123", 1073741824)
	if err != nil {
		t.Fatalf("failed to create mailbox: %v", err)
	}

	// 3. Test Passdb Lookup & Argon2id Authentication
	t.Run("Auth: active + ready + correct PW -> PASS", func(t *testing.T) {
		err := dovecotSvc.Authenticate(ctx, "ajar@example.com", "SecurePass123")
		if err != nil {
			t.Errorf("expected authentication success, got %v", err)
		}
	})

	t.Run("Auth: case-insensitive uppercase -> PASS", func(t *testing.T) {
		err := dovecotSvc.Authenticate(ctx, "AJAR@EXAMPLE.COM", "SecurePass123")
		if err != nil {
			t.Errorf("expected uppercase username auth to succeed, got %v", err)
		}
	})

	t.Run("Auth: active + ready + wrong PW -> FAIL", func(t *testing.T) {
		err := dovecotSvc.Authenticate(ctx, "ajar@example.com", "WrongPassword")
		if err != dovecot.ErrAuthenticationFailed {
			t.Errorf("expected ErrAuthenticationFailed, got %v", err)
		}
	})

	t.Run("Auth: unknown user -> FAIL", func(t *testing.T) {
		err := dovecotSvc.Authenticate(ctx, "ghost@example.com", "SecurePass123")
		if err != dovecot.ErrAuthenticationFailed {
			t.Errorf("expected ErrAuthenticationFailed, got %v", err)
		}
	})

	t.Run("Auth: suspended user -> FAIL", func(t *testing.T) {
		_ = mailboxRepo.UpdateStatus(ctx, mb.ID, "suspended")
		err := dovecotSvc.Authenticate(ctx, "ajar@example.com", "SecurePass123")
		if err != dovecot.ErrAuthenticationFailed {
			t.Errorf("expected suspended user to fail authentication, got %v", err)
		}
		_ = mailboxRepo.UpdateStatus(ctx, mb.ID, "active")
	})

	t.Run("Auth: pending user -> FAIL", func(t *testing.T) {
		_ = mailboxRepo.UpdateProvisioningStatus(ctx, mb.ID, mailbox.ProvisioningPending)
		err := dovecotSvc.Authenticate(ctx, "ajar@example.com", "SecurePass123")
		if err != dovecot.ErrAuthenticationFailed {
			t.Errorf("expected pending user to fail authentication, got %v", err)
		}
		_ = mailboxRepo.UpdateProvisioningStatus(ctx, mb.ID, mailbox.ProvisioningReady)
	})

	// 4. Test Userdb Lookup (Derived Maildir Location)
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

	// 5. Test Live IMAP Server (if port 143 is reachable on host)
	t.Run("Live IMAP: Port 143 session", func(t *testing.T) {
		conn, err := net.DialTimeout("tcp", "127.0.0.1:143", 500*time.Millisecond)
		if err != nil {
			t.Skip("IMAP service not running on 127.0.0.1:143, skipping live socket test")
			return
		}
		defer conn.Close()

		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			t.Fatalf("failed reading greeting: %v", err)
		}
		greeting := string(buf[:n])
		if !strings.Contains(greeting, "Dovecot ready") && !strings.Contains(greeting, "OK") {
			t.Errorf("unexpected IMAP greeting: %s", greeting)
		}
	})
}
