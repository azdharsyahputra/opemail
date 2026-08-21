package tests

import (
	"bytes"
	"context"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/azdharsyahputra/openmail/internal/config"
	"github.com/azdharsyahputra/openmail/internal/database"
	"github.com/azdharsyahputra/openmail/internal/domain"
	"github.com/azdharsyahputra/openmail/internal/mailbox"
	"github.com/azdharsyahputra/openmail/internal/message"
	"github.com/azdharsyahputra/openmail/internal/storage"
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

	// Run migrations up (runs 000001 and 000002)
	if err := database.RunMigrationsUp(db); err != nil {
		t.Fatalf("failed to run migrations up: %v", err)
	}
	defer database.RunMigrationsDown(db)

	tempDir, err := os.MkdirTemp("", "openmail-integration-blobs-*")
	if err != nil {
		t.Fatalf("failed to create temp blob directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	blobStore, err := storage.NewFilesystemBlobStore(tempDir)
	if err != nil {
		t.Fatalf("failed to create blob store: %v", err)
	}

	ctx := context.Background()
	domainRepo := domain.NewPostgresRepository(db)
	mailboxRepo := mailbox.NewPostgresRepository(db)
	messageRepo := message.NewPostgresRepository(db)

	domainSvc := domain.NewService(domainRepo)
	mailboxSvc := mailbox.NewService(mailboxRepo, domainRepo)
	messageSvc := message.NewService(messageRepo, mailboxRepo, blobStore)

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

	// 7. Store Message into Mailbox & BlobStore
	rawEmail := "Message-ID: <msg-001@example.com>\r\n" +
		"From: sender@domain.com\r\n" +
		"To: ajar@example.com\r\n" +
		"Subject: Welcome to OpenMail\r\n" +
		"Date: Fri, 21 Aug 2026 14:00:00 +0000\r\n\r\n" +
		"Hello Ajar, this is your first email payload."

	msg, err := messageSvc.Store(ctx, "ajar@example.com", strings.NewReader(rawEmail))
	if err != nil {
		t.Fatalf("expected no error storing message, got %v", err)
	}
	if msg.Subject != "Welcome to OpenMail" {
		t.Errorf("expected subject 'Welcome to OpenMail', got %s", msg.Subject)
	}
	if msg.Sender != "sender@domain.com" {
		t.Errorf("expected sender 'sender@domain.com', got %s", msg.Sender)
	}

	// 8. Verify Blob exists on disk
	exists, err := blobStore.Exists(ctx, msg.BlobID)
	if err != nil || !exists {
		t.Errorf("expected blob %s to exist in blobstore, exists=%v, err=%v", msg.BlobID, exists, err)
	}

	// 9. Get Message Content
	gotMsg, reader, err := messageSvc.GetContent(ctx, msg.ID)
	if err != nil {
		t.Fatalf("expected no error getting message content, got %v", err)
	}
	defer reader.Close()

	buf := new(bytes.Buffer)
	_, _ = io.Copy(buf, reader)
	if buf.String() != rawEmail {
		t.Errorf("expected raw payload %q, got %q", rawEmail, buf.String())
	}
	if gotMsg.ID != msg.ID {
		t.Errorf("expected msg ID %s, got %s", msg.ID, gotMsg.ID)
	}

	// 10. List Messages for Mailbox
	msgList, err := messageSvc.ListByMailbox(ctx, "ajar@example.com")
	if err != nil {
		t.Fatalf("expected no error listing messages, got %v", err)
	}
	if len(msgList) != 1 {
		t.Errorf("expected 1 message in mailbox, got %d", len(msgList))
	}

	// 11. Delete Message
	if err := messageSvc.Delete(ctx, msg.ID); err != nil {
		t.Fatalf("expected no error deleting message, got %v", err)
	}
	exists, err = blobStore.Exists(ctx, msg.BlobID)
	if err != nil || exists {
		t.Errorf("expected blob to be removed after message deletion, exists=%v", exists)
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
