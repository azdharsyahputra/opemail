package tests

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/azdharsyahputra/openmail/internal/config"
	"github.com/azdharsyahputra/openmail/internal/database"
	"github.com/azdharsyahputra/openmail/internal/domain"
	"github.com/azdharsyahputra/openmail/internal/mailbox"
	"github.com/azdharsyahputra/openmail/internal/message"
	"github.com/azdharsyahputra/openmail/internal/provisioning"
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

	// Run migrations up (runs 000001, 000002, 000003)
	if err := database.RunMigrationsUp(db); err != nil {
		t.Fatalf("failed to run migrations up: %v", err)
	}
	defer database.RunMigrationsDown(db)

	tempBlobDir, err := os.MkdirTemp("", "openmail-integration-blobs-*")
	if err != nil {
		t.Fatalf("failed to create temp blob directory: %v", err)
	}
	defer os.RemoveAll(tempBlobDir)

	blobStore, err := storage.NewFilesystemBlobStore(tempBlobDir)
	if err != nil {
		t.Fatalf("failed to create blob store: %v", err)
	}

	tempVmailDir, err := os.MkdirTemp("", "openmail-integration-vmail-*")
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
	messageRepo := message.NewPostgresRepository(db)

	domainSvc := domain.NewService(domainRepo)
	mailboxSvc := mailbox.NewService(mailboxRepo, domainRepo, prov)
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

	// 4. Create Mailbox & Verify Automatic Provisioning to Ready
	mb, err := mailboxSvc.Create(ctx, "ajar@example.com", "securepass123", 1073741824)
	if err != nil {
		t.Fatalf("expected no error creating mailbox, got %v", err)
	}
	if mb.Email != "ajar@example.com" {
		t.Errorf("expected email ajar@example.com, got %s", mb.Email)
	}
	if mb.ProvisioningStatus != mailbox.ProvisioningReady {
		t.Errorf("expected provisioning_status ready, got %s", mb.ProvisioningStatus)
	}

	// Check filesystem Dovecot Maildir++ layout
	maildirPath := filepath.Join(tempVmailDir, "example.com", "ajar", "Maildir")
	subdirs := []string{"", "cur", "new", "tmp"}
	for _, sub := range subdirs {
		dir := filepath.Join(maildirPath, sub)
		info, err := os.Stat(dir)
		if err != nil || !info.IsDir() {
			t.Errorf("expected directory %s to exist, err=%v", dir, err)
		}
		if perm := info.Mode().Perm(); perm != 0750 {
			t.Errorf("expected permission 0750 on %s, got %04o", dir, perm)
		}
	}

	// 5. Test Mailbox Doctor
	doctorReport, err := mailboxSvc.Doctor(ctx, "ajar@example.com")
	if err != nil {
		t.Fatalf("expected no error from doctor, got %v", err)
	}
	if !doctorReport.Healthy {
		t.Errorf("expected mailbox to be healthy, got %+v", doctorReport)
	}

	// 6. Test Idempotent Provisioning
	_, alreadyProvisioned, err := mailboxSvc.Provision(ctx, "ajar@example.com")
	if err != nil {
		t.Fatalf("expected no error from provision call, got %v", err)
	}
	if !alreadyProvisioned {
		t.Errorf("expected alreadyProvisioned=true for ready mailbox")
	}

	// Verify Argon2id password hash format and valid password check
	if valid, err := mailboxSvc.VerifyPassword("securepass123", mb.PasswordHash); err != nil || !valid {
		t.Errorf("password verification failed: valid=%v, err=%v", valid, err)
	}

	// 7. Get Mailbox
	gotMb, err := mailboxSvc.GetByEmail(ctx, "ajar@example.com")
	if err != nil {
		t.Fatalf("expected no error getting mailbox, got %v", err)
	}
	if gotMb.ID != mb.ID {
		t.Errorf("expected mailbox ID %s, got %s", mb.ID, gotMb.ID)
	}
	if gotMb.ProvisioningStatus != mailbox.ProvisioningReady {
		t.Errorf("expected provisioning status ready in DB, got %s", gotMb.ProvisioningStatus)
	}

	// 8. List Mailboxes
	list, err := mailboxSvc.List(ctx)
	if err != nil {
		t.Fatalf("expected no error listing mailboxes, got %v", err)
	}
	if len(list) != 1 {
		t.Errorf("expected 1 mailbox, got %d", len(list))
	}

	// 9. Store Message into Mailbox & BlobStore
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

	// 10. Get Message Content
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

	// 11. Delete Message
	if err := messageSvc.Delete(ctx, msg.ID); err != nil {
		t.Fatalf("expected no error deleting message, got %v", err)
	}

	// 12. Delete Mailbox & Verify Deprovisioning on Filesystem and DB Deletion
	if err := mailboxSvc.Delete(ctx, "ajar@example.com"); err != nil {
		t.Fatalf("expected no error deleting mailbox, got %v", err)
	}

	_, err = mailboxSvc.GetByEmail(ctx, "ajar@example.com")
	if err != mailbox.ErrMailboxNotFound {
		t.Errorf("expected ErrMailboxNotFound after deletion, got %v", err)
	}

	// Verify filesystem Maildir removed
	if _, err := os.Stat(maildirPath); !os.IsNotExist(err) {
		t.Errorf("expected %s to be deleted after mailbox deletion", maildirPath)
	}
}
