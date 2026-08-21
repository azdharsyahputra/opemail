package tests

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/azdharsyahputra/openmail/internal/abuse"
	"github.com/azdharsyahputra/openmail/internal/config"
	"github.com/azdharsyahputra/openmail/internal/database"
	"github.com/azdharsyahputra/openmail/internal/domain"
	"github.com/azdharsyahputra/openmail/internal/inbound"
	"github.com/azdharsyahputra/openmail/internal/mailbox"
	"github.com/azdharsyahputra/openmail/internal/provisioning"
)

func TestIntegration_AbuseAndRateLimiting(t *testing.T) {
	ctx := context.Background()

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
		t.Skipf("Skipping abuse integration test: PostgreSQL unavailable (%v)", err)
		return
	}
	defer db.Close()

	if err := database.RunMigrationsUp(db); err != nil {
		t.Fatalf("failed to run migrations: %v", err)
	}


	tempVmailDir, err := os.MkdirTemp("", "openmail-abuse-vmail-*")
	if err != nil {
		t.Fatalf("temp vmail error: %v", err)
	}
	defer os.RemoveAll(tempVmailDir)

	prov, err := provisioning.NewFilesystemProvisioner(tempVmailDir, 5000, 5000)
	if err != nil {
		t.Fatalf("provisioner error: %v", err)
	}

	domainRepo := domain.NewPostgresRepository(db)
	mailboxRepo := mailbox.NewPostgresRepository(db)
	abuseRepo := abuse.NewPostgresRepository(db)

	domainSvc := domain.NewService(domainRepo)
	mailboxSvc := mailbox.NewService(mailboxRepo, domainRepo, prov)
	abuseSvc := abuse.NewService(abuseRepo, mailboxRepo)

	testDomain := "abuse-check.com"
	_, _ = domainSvc.Create(ctx, testDomain)

	testMailbox := "abuse-test@" + testDomain
	_, _ = mailboxSvc.Create(ctx, testMailbox, "StrongPass123!", 1073741824)


	t.Run("Mailbox Limits CRUD: Default, Update, Retrieve", func(t *testing.T) {
		// 1. Get default limits
		limits, err := abuseSvc.GetLimits(ctx, testMailbox)
		if err != nil {
			t.Fatalf("get limits error: %v", err)
		}
		if limits.MessagesPerMinute != 30 || limits.MessagesPerHour != 300 || limits.RecipientsPerDay != 1000 {
			t.Errorf("unexpected default limits: %+v", limits)
		}

		// 2. Set custom limits
		custom := &abuse.MailboxLimits{
			MessagesPerMinute: 10,
			MessagesPerHour:   100,
			RecipientsPerDay:  500,
			Enabled:           true,
		}
		if err := abuseSvc.SetLimits(ctx, testMailbox, custom); err != nil {
			t.Fatalf("set limits error: %v", err)
		}

		// 3. Verify retrieved updated limits
		updated, err := abuseSvc.GetLimits(ctx, testMailbox)
		if err != nil {
			t.Fatalf("get updated limits error: %v", err)
		}
		if updated.MessagesPerMinute != 10 || updated.MessagesPerHour != 100 || updated.RecipientsPerDay != 500 {
			t.Errorf("expected updated limits, got: %+v", updated)
		}
	})

	t.Run("Memory Sliding Window Rate Limiter", func(t *testing.T) {
		limiter := inbound.NewMemoryRateLimiter(inbound.RateLimitPolicy{
			MaxConnectionsPerIP: 3,
			MaxMessagesPerIP:    3,
			Window:              500 * time.Millisecond,
		})

		testIP := "198.51.100.99"

		// Connections 1, 2, 3 -> Allow
		if !limiter.AllowConnection(testIP) || !limiter.AllowConnection(testIP) || !limiter.AllowConnection(testIP) {
			t.Errorf("expected first 3 connections to be allowed")
		}

		// Connection 4 -> Blocked
		if limiter.AllowConnection(testIP) {
			t.Errorf("expected 4th connection to be blocked")
		}

		// Messages 1, 2, 3 -> Allow
		if !limiter.AllowMessage(testIP) || !limiter.AllowMessage(testIP) || !limiter.AllowMessage(testIP) {
			t.Errorf("expected first 3 messages to be allowed")
		}

		// Message 4 -> Blocked
		if limiter.AllowMessage(testIP) {
			t.Errorf("expected 4th message to be blocked")
		}

		// After window expires -> Allowed again
		time.Sleep(600 * time.Millisecond)
		if !limiter.AllowConnection(testIP) {
			t.Errorf("expected connection to be allowed after window reset")
		}
	})
}
