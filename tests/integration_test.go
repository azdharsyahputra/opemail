package tests

import (
	"context"
	"os"
	"strings"
	"testing"



	"github.com/azdharsyahputra/openmail/internal/config"
	"github.com/azdharsyahputra/openmail/internal/database"
	"github.com/azdharsyahputra/openmail/internal/domain"
	"github.com/azdharsyahputra/openmail/internal/mailbox"
	"github.com/azdharsyahputra/openmail/internal/message"
	"github.com/azdharsyahputra/openmail/internal/postfix"
	"github.com/azdharsyahputra/openmail/internal/provisioning"
	"github.com/azdharsyahputra/openmail/internal/storage"
	"github.com/google/uuid"
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

	// Run migrations up (runs 000001, 000002, 000003, 000004, 000005)
	if err := database.RunMigrationsUp(db); err != nil {
		t.Fatalf("failed to run migrations up: %v", err)
	}



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
	postfixRepo := postfix.NewPostgresRepository(db)

	domainSvc := domain.NewService(domainRepo)
	mailboxSvc := mailbox.NewService(mailboxRepo, domainRepo, prov)
	messageSvc := message.NewService(messageRepo, mailboxRepo, blobStore)
	postfixSvc := postfix.NewService(postfixRepo, postfix.NewSystemProvisioner("/tmp"))

	// 1. Create Domain (active)
	_ = domainSvc.Delete(ctx, "example.com")
	dom, err := domainSvc.Create(ctx, "example.com")
	if err != nil {
		t.Fatalf("expected no error creating domain, got %v", err)
	}

	if dom.Name != "example.com" {
		t.Errorf("expected domain name example.com, got %s", dom.Name)
	}

	// 2. Postfix Domain Lookup test (case-insensitive)
	found, err := postfixRepo.LookupVirtualDomain(ctx, "example.com")
	if err != nil || !found {
		t.Errorf("expected domain example.com to be found by postfix, found=%v err=%v", found, err)
	}
	found, err = postfixRepo.LookupVirtualDomain(ctx, "EXAMPLE.COM")
	if err != nil || !found {
		t.Errorf("expected domain EXAMPLE.COM case-insensitive lookup to pass, found=%v err=%v", found, err)
	}
	found, err = postfixRepo.LookupVirtualDomain(ctx, "unknown.com")
	if err != nil || found {
		t.Errorf("expected unknown domain to return false, found=%v err=%v", found, err)
	}

	// 3. Create Mailbox & Verify Automatic Provisioning to Ready
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

	// 4. Postfix Mailbox Lookup test (case-insensitive & ready check)
	found, err = postfixRepo.LookupVirtualMailbox(ctx, "ajar@example.com")
	if err != nil || !found {
		t.Errorf("expected mailbox ajar@example.com to be found by postfix, found=%v err=%v", found, err)
	}
	found, err = postfixRepo.LookupVirtualMailbox(ctx, "AJAR@EXAMPLE.COM")
	if err != nil || !found {
		t.Errorf("expected mailbox AJAR@EXAMPLE.COM case-insensitive to pass, found=%v err=%v", found, err)
	}
	found, err = postfixRepo.LookupVirtualMailbox(ctx, "ghost@example.com")
	if err != nil || found {
		t.Errorf("expected unknown mailbox in valid domain to return false, found=%v err=%v", found, err)
	}

	// 5. Test Non-Ready and Suspended Mailbox Lookup Filtering
	_ = mailboxRepo.UpdateProvisioningStatus(ctx, mb.ID, mailbox.ProvisioningFailed)
	found, err = postfixRepo.LookupVirtualMailbox(ctx, "ajar@example.com")
	if err != nil || found {
		t.Errorf("expected failed provisioning mailbox to be rejected by postfix lookup, found=%v", found)
	}
	_ = mailboxRepo.UpdateProvisioningStatus(ctx, mb.ID, mailbox.ProvisioningReady)

	_ = mailboxRepo.UpdateStatus(ctx, mb.ID, "suspended")
	found, err = postfixRepo.LookupVirtualMailbox(ctx, "ajar@example.com")
	if err != nil || found {
		t.Errorf("expected suspended mailbox to be rejected by postfix lookup, found=%v", found)
	}
	_ = mailboxRepo.UpdateStatus(ctx, mb.ID, "active")

	// 6. Test Alias Lookup in PostgreSQL
	aliasQuery := `INSERT INTO aliases (id, domain_id, source, destination, created_at) VALUES ($1, $2, $3, $4, NOW())`
	_, err = db.ExecContext(ctx, aliasQuery, uuid.New(), dom.ID, "support@example.com", "ajar@example.com")
	if err != nil {
		t.Fatalf("failed to insert test alias: %v", err)
	}

	aliases, err := postfixRepo.LookupVirtualAlias(ctx, "support@example.com")
	if err != nil || len(aliases) != 1 || aliases[0] != "ajar@example.com" {
		t.Errorf("expected alias lookup to return ajar@example.com, got %v, err=%v", aliases, err)
	}

	// 7. Test MailTransport Decoupled Recipient Validation
	valid, err := postfixSvc.ValidateRecipient(ctx, "ajar@example.com")
	if err != nil || !valid {
		t.Errorf("expected ajar@example.com recipient to be valid, valid=%v err=%v", valid, err)
	}
	valid, err = postfixSvc.ValidateRecipient(ctx, "support@example.com")
	if err != nil || !valid {
		t.Errorf("expected support@example.com alias to be valid recipient, valid=%v err=%v", valid, err)
	}
	valid, err = postfixSvc.ValidateRecipient(ctx, "nonexistent@example.com")
	if err != postfix.ErrMailboxNotFound || valid {
		t.Errorf("expected ErrMailboxNotFound for nonexistent recipient, valid=%v err=%v", valid, err)
	}
	valid, err = postfixSvc.ValidateRecipient(ctx, "user@otherdomain.com")
	if err != postfix.ErrDomainNotFound || valid {
		t.Errorf("expected ErrDomainNotFound for outside domain, valid=%v err=%v", valid, err)
	}

	// 8. Test Mailbox Doctor
	doctorReport, err := mailboxSvc.Doctor(ctx, "ajar@example.com")
	if err != nil {
		t.Fatalf("expected no error from doctor, got %v", err)
	}
	if !doctorReport.Healthy {
		t.Errorf("expected mailbox to be healthy, got %+v", doctorReport)
	}

	// 9. Store and retrieve email message
	rawEmail := "From: sender@domain.com\r\nTo: ajar@example.com\r\nSubject: Test Email\r\n\r\nHello Ajar"
	msg, err := messageSvc.Store(ctx, "ajar@example.com", strings.NewReader(rawEmail))
	if err != nil {
		t.Fatalf("expected no error storing message: %v", err)
	}
	_ = messageSvc.Delete(ctx, msg.ID)

	// 10. Delete Mailbox & Verify Deprovisioning
	if err := mailboxSvc.Delete(ctx, "ajar@example.com"); err != nil {
		t.Fatalf("expected no error deleting mailbox: %v", err)
	}
	found, _ = postfixRepo.LookupVirtualMailbox(ctx, "ajar@example.com")
	if found {
		t.Error("expected deleted mailbox to not be found by postfix")
	}
}
