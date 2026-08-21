package tests

import (
	"context"
	"os"
	"testing"

	"github.com/azdharsyahputra/openmail/internal/config"
	"github.com/azdharsyahputra/openmail/internal/database"
	"github.com/azdharsyahputra/openmail/internal/domain"
	"github.com/azdharsyahputra/openmail/internal/mailbox"
)

func TestIntegration_PostgreSQL(t *testing.T) {
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

	// Clean up database tables before test
	_ = database.RunMigrationsDown(db)

	// Run migrations up
	if err := database.RunMigrationsUp(db); err != nil {
		t.Fatalf("failed to run migrations up: %v", err)
	}
	defer database.RunMigrationsDown(db)

	ctx := context.Background()
	domainRepo := domain.NewPostgresRepository(db)
	mailboxRepo := mailbox.NewPostgresRepository(db)

	domainSvc := domain.NewService(domainRepo)
	mailboxSvc := mailbox.NewService(mailboxRepo, domainRepo)

	// 1. Create Domain
	dom, err := domainSvc.Create(ctx, "example.com")
	if err != nil {
		t.Fatalf("expected no error creating domain, got %v", err)
	}
	if dom.Name != "example.com" {
		t.Errorf("expected domain name example.com, got %s", dom.Name)
	}

	// 2. Duplicate Domain Error
	_, err = domainSvc.Create(ctx, "example.com")
	if err != domain.ErrDomainExists {
		t.Errorf("expected ErrDomainExists, got %v", err)
	}

	// 3. Invalid Domain Error
	_, err = domainSvc.Create(ctx, "invalid_domain")
	if err != domain.ErrInvalidDomain {
		t.Errorf("expected ErrInvalidDomain, got %v", err)
	}

	// 4. Create Mailbox
	mb, err := mailboxSvc.Create(ctx, "ajar@example.com", "securepass123", 1073741824)
	if err != nil {
		t.Fatalf("expected no error creating mailbox, got %v", err)
	}
	if mb.Email != "ajar@example.com" {
		t.Errorf("expected email ajar@example.com, got %s", mb.Email)
	}

	// Verify Argon2id password hash format and valid password check
	if valid, err := mailboxSvc.VerifyPassword("securepass123", mb.PasswordHash); err != nil || !valid {
		t.Errorf("password verification failed: valid=%v, err=%v", valid, err)
	}

	// 5. Get Mailbox
	gotMb, err := mailboxSvc.GetByEmail(ctx, "ajar@example.com")
	if err != nil {
		t.Fatalf("expected no error getting mailbox, got %v", err)
	}
	if gotMb.ID != mb.ID {
		t.Errorf("expected mailbox ID %s, got %s", mb.ID, gotMb.ID)
	}

	// 6. List Mailboxes
	list, err := mailboxSvc.List(ctx)
	if err != nil {
		t.Fatalf("expected no error listing mailboxes, got %v", err)
	}
	if len(list) != 1 {
		t.Errorf("expected 1 mailbox, got %d", len(list))
	}

	// 7. Duplicate Mailbox Error
	_, err = mailboxSvc.Create(ctx, "ajar@example.com", "securepass123", 1073741824)
	if err != mailbox.ErrMailboxExists {
		t.Errorf("expected ErrMailboxExists, got %v", err)
	}

	// 8. Nonexistent Domain Mailbox Error
	_, err = mailboxSvc.Create(ctx, "user@nonexistent.com", "securepass123", 1073741824)
	if err != mailbox.ErrDomainNotFound {
		t.Errorf("expected ErrDomainNotFound, got %v", err)
	}

	// 9. Invalid Email Error
	_, err = mailboxSvc.Create(ctx, "invalidemail", "securepass123", 1073741824)
	if err != mailbox.ErrInvalidEmail {
		t.Errorf("expected ErrInvalidEmail, got %v", err)
	}

	// 10. Weak Password Error
	_, err = mailboxSvc.Create(ctx, "weak@example.com", "123", 1073741824)
	if err != mailbox.ErrInvalidPassword {
		t.Errorf("expected ErrInvalidPassword, got %v", err)
	}

	// 11. Delete Nonexistent Mailbox Error
	err = mailboxSvc.Delete(ctx, "nonexistent@example.com")
	if err != mailbox.ErrMailboxNotFound {
		t.Errorf("expected ErrMailboxNotFound, got %v", err)
	}

	// 12. Delete Mailbox & Verify Deleted
	if err := mailboxSvc.Delete(ctx, "ajar@example.com"); err != nil {
		t.Fatalf("expected no error deleting mailbox, got %v", err)
	}

	_, err = mailboxSvc.GetByEmail(ctx, "ajar@example.com")
	if err != mailbox.ErrMailboxNotFound {
		t.Errorf("expected ErrMailboxNotFound after deletion, got %v", err)
	}
}
