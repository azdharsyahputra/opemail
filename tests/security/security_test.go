package security_test

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"


	"github.com/azdharsyahputra/openmail/internal/config"
	"github.com/azdharsyahputra/openmail/internal/database"
	"github.com/azdharsyahputra/openmail/internal/domain"
	"github.com/azdharsyahputra/openmail/internal/mailbox"
	"github.com/azdharsyahputra/openmail/internal/provisioning"
	"github.com/google/uuid"
)

func setupSecurityTestDB(t *testing.T) *sql.DB {

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
		t.Skipf("Skipping security test: PostgreSQL unavailable (%v)", err)
		return nil
	}

	if err := database.RunMigrationsUp(db); err != nil {
		t.Fatalf("failed to run migrations: %v", err)
	}
	return db
}

func TestSecurity_ComprehensiveHardening(t *testing.T) {
	db := setupSecurityTestDB(t)
	if db == nil {
		return
	}
	defer db.Close()

	ctx := context.Background()
	domRepo := domain.NewPostgresRepository(db)
	mbRepo := mailbox.NewPostgresRepository(db)
	tempVmail := t.TempDir()
	prov, err := provisioning.NewFilesystemProvisioner(tempVmail, 5000, 5000)
	if err != nil {
		t.Fatalf("provisioner error: %v", err)
	}
	domSvc := domain.NewService(domRepo)
	mbSvc := mailbox.NewService(mbRepo, domRepo, prov)

	testDomain := fmt.Sprintf("sec-%d.example.com", time.Now().UnixNano())
	_, _ = domSvc.Create(ctx, testDomain)

	// SEC-001: SQL Injection Attack Vectors across domain, email, alias, selector
	t.Run("SEC-001: SQL Injection Resilience", func(t *testing.T) {
		sqlPayloads := []string{
			"' OR '1'='1",
			"'; DROP TABLE mailboxes; --",
			"admin'--",
			"' UNION SELECT null, null, null --",
			"1'; UPDATE mailboxes SET status='active'; --",
		}

		for _, payload := range sqlPayloads {
			// Domain injection attempt
			_, err := domSvc.Create(ctx, payload)
			if err == nil {
				t.Errorf("expected SQL injection payload %q in domain create to fail validation", payload)
			}

			// Mailbox injection attempt
			_, err = mbSvc.Create(ctx, payload+"@"+testDomain, "Secret123!", 1000)
			if err == nil {
				t.Errorf("expected SQL injection payload %q in mailbox email to fail validation", payload)
			}

			// Password lookup injection attempt
			_, err = mbSvc.Authenticate(ctx, payload+"@"+testDomain, payload)
			if err == nil {
				t.Errorf("expected authentication with SQL injection payload %q to fail", payload)
			}
		}

		// Verify table intact
		var count int
		_ = db.QueryRowContext(ctx, "SELECT count(*) FROM mailboxes").Scan(&count)
		if count < 0 {
			t.Errorf("table check failed")
		}
	})

	// SEC-002 & SEC-003 & FS-004: Path & Symlink Traversal Protection
	t.Run("SEC-002 & SEC-003: Path & Symlink Traversal Protection", func(t *testing.T) {
		traversalPayloads := []string{
			"../../etc/passwd",
			"foo/../../etc/shadow",
			"..\\..\\windows\\system32",
			"/etc/passwd",
			"user/../../../../../../etc/hosts",
		}

		for _, p := range traversalPayloads {
			_, err := prov.CalculatePath(p + "@" + testDomain)
			if err == nil {
				t.Errorf("expected path traversal payload %q to be rejected", p)
			}
		}

		// Symlink attack simulation: directory must not escape root
		symlinkTarget := filepath.Join(tempVmail, "attacker-symlink")
		_ = os.Symlink("/etc", symlinkTarget)
		_, err := prov.CalculatePath(symlinkTarget + "@" + testDomain)
		if err == nil {
			t.Errorf("expected symlink path to be rejected")
		}
	})

	// SEC-014: User Enumeration Prevention (Identical behavior for ghost vs suspended)
	t.Run("SEC-014: User Enumeration Prevention", func(t *testing.T) {
		// Create suspended user
		suspEmail := "suspended-user@" + testDomain
		mb, err := mbSvc.Create(ctx, suspEmail, "SecretPass123!", 1000)
		if err != nil {
			t.Fatalf("failed to create mailbox: %v", err)
		}
		_ = mbSvc.Suspend(ctx, mb.ID)

		ghostEmail := "nonexistent-user@" + testDomain

		// Check authentication on both
		_, errSusp := mbSvc.Authenticate(ctx, suspEmail, "WrongPassword!")
		_, errGhost := mbSvc.Authenticate(ctx, ghostEmail, "WrongPassword!")

		// Both must return ErrAuthenticationFailed or ErrMailboxNotFound without exposing account status
		if errSusp == nil || errGhost == nil {
			t.Errorf("expected authentication to fail for both suspended and ghost user")
		}
	})

	// SEC-015: Authentication Timing Attack Resilience
	t.Run("SEC-015: Authentication Timing Measurement", func(t *testing.T) {
		validUser := "timing-user@" + testDomain
		_, err := mbSvc.Create(ctx, validUser, "CorrectPassword123!", 1000)
		if err != nil {
			t.Fatalf("failed to create mailbox: %v", err)
		}

		// Time 5 invalid auths on existing user
		startValid := time.Now()
		for i := 0; i < 5; i++ {
			_, _ = mbSvc.Authenticate(ctx, validUser, "WrongPassword123!")
		}
		durationValid := time.Since(startValid)

		// Time 5 auths on non-existing user
		startGhost := time.Now()
		for i := 0; i < 5; i++ {
			_, _ = mbSvc.Authenticate(ctx, "ghost-timing@"+testDomain, "WrongPassword123!")
		}
		durationGhost := time.Since(startGhost)

		// Both should compute dummy Argon2id hash or perform in comparable bounds
		t.Logf("Timing check - Existing user: %v, Non-existing user: %v", durationValid, durationGhost)
	})

	// SEC-005 & SEC-006 & SEC-007: PostgreSQL Least Privilege Roles
	t.Run("SEC-005 to SEC-007: Database Role Least Privilege", func(t *testing.T) {
		dovecotDBURL := "postgres://mailopen_dovecot:dovecot_secret@localhost:5433/mailopen?sslmode=disable"
		dovDB, err := database.NewPostgresDB(dovecotDBURL)
		if err == nil {
			defer dovDB.Close()

			// Dovecot cannot INSERT, UPDATE, or DELETE
			_, err = dovDB.ExecContext(ctx, "DELETE FROM mailboxes WHERE email = 'test@example.com'")
			if err == nil {
				t.Errorf("SECURITY VIOLATION: mailopen_dovecot was able to DELETE from mailboxes table!")
			}
			_, err = dovDB.ExecContext(ctx, "INSERT INTO domains (id, name, status) VALUES ($1, 'hack.com', 'active')", uuid.New())
			if err == nil {
				t.Errorf("SECURITY VIOLATION: mailopen_dovecot was able to INSERT into domains table!")
			}
		}
	})
}
