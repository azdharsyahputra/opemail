package concurrency_test

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/azdharsyahputra/openmail/internal/config"
	"github.com/azdharsyahputra/openmail/internal/database"
	"github.com/azdharsyahputra/openmail/internal/domain"
	"github.com/azdharsyahputra/openmail/internal/mailbox"
	"github.com/azdharsyahputra/openmail/internal/provisioning"
	"github.com/azdharsyahputra/openmail/internal/quota"
)

func setupConcurrencyTestDB(t *testing.T) *sql.DB {

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
		t.Skipf("Skipping concurrency test: PostgreSQL unavailable (%v)", err)
		return nil
	}

	if err := database.RunMigrationsUp(db); err != nil {
		t.Fatalf("failed to run migrations: %v", err)
	}
	return db
}

func TestConcurrency_Matrix(t *testing.T) {
	db := setupConcurrencyTestDB(t)
	if db == nil {
		return
	}
	defer db.Close()

	ctx := context.Background()
	domRepo := domain.NewPostgresRepository(db)
	mbRepo := mailbox.NewPostgresRepository(db)
	prov, _ := provisioning.NewFilesystemProvisioner(t.TempDir(), 5000, 5000)
	domSvc := domain.NewService(domRepo)
	mbSvc := mailbox.NewService(mbRepo, domRepo, prov)
	quotaSvc := quota.NewService(mbRepo, prov)

	testDomain := fmt.Sprintf("conc-%d.example.com", time.Now().UnixNano())
	_, _ = domSvc.Create(ctx, testDomain)

	// CONC-004 & DB-004: Concurrent Mailbox Creation for the Exact Same Email
	t.Run("CONC-004: Concurrent Same-Email Mailbox Creation", func(t *testing.T) {
		targetEmail := "race-mailbox@" + testDomain
		var wg sync.WaitGroup
		var successCount int32
		var failCount int32

		concurrency := 10
		for i := 0; i < concurrency; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, err := mbSvc.Create(ctx, targetEmail, "SecurePassword123!", 1073741824)
				if err == nil {
					atomic.AddInt32(&successCount, 1)
				} else {
					atomic.AddInt32(&failCount, 1)
				}
			}()
		}

		wg.Wait()

		if successCount != 1 {
			t.Errorf("expected exactly 1 success for concurrent mailbox create, got: %d (fails: %d)", successCount, failCount)
		}
	})

	// CONC-003: 100 Concurrent Mailbox Lookups
	t.Run("CONC-003: 100 Concurrent Mailbox Lookups", func(t *testing.T) {
		lookupEmail := "lookup-target@" + testDomain
		_, _ = mbSvc.Create(ctx, lookupEmail, "SecurePassword123!", 1073741824)

		var wg sync.WaitGroup
		errChan := make(chan error, 100)

		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				mb, err := mbRepo.GetByEmail(ctx, lookupEmail)
				if err != nil || mb == nil {
					errChan <- fmt.Errorf("lookup failed: %v", err)
				}
			}()
		}

		wg.Wait()
		close(errChan)

		for err := range errChan {
			t.Errorf("concurrent lookup error: %v", err)
		}
	})

	// CONC-005: Concurrent Password Updates + Authentications
	t.Run("CONC-005: Concurrent Password Update and Authentication", func(t *testing.T) {
		authEmail := "auth-race@" + testDomain
		_, _ = mbSvc.Create(ctx, authEmail, "InitialPass123!", 1073741824)

		var wg sync.WaitGroup
		// 5 password updaters
		for i := 0; i < 5; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				newPass := fmt.Sprintf("UpdatedPass%d!", idx)
				_ = mbSvc.SetPassword(ctx, authEmail, newPass)
			}(i)
		}

		// 20 concurrent auth attempts
		for i := 0; i < 20; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, _ = mbSvc.Authenticate(ctx, authEmail, "InitialPass123!")
			}()
		}

		wg.Wait()

		// Mailbox must still exist and be authenticatable
		mb, err := mbRepo.GetByEmail(ctx, authEmail)
		if err != nil || mb == nil {
			t.Fatalf("mailbox corrupt after concurrent updates: %v", err)
		}
	})

	// CONC-007: Concurrent Quota Reconciliation and Delivery Acceptance
	t.Run("CONC-007: Concurrent Quota Reconciler & Inbound Check", func(t *testing.T) {
		quotaEmail := "quota-race@" + testDomain
		_, _ = mbSvc.Create(ctx, quotaEmail, "Pass123!", 10000)

		var wg sync.WaitGroup
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, _ = quotaSvc.Reconcile(ctx, quotaEmail)
			}()
		}

		for i := 0; i < 20; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, _ = quotaSvc.CheckCanAccept(ctx, quotaEmail, 500)
			}()
		}

		wg.Wait()
	})
}
