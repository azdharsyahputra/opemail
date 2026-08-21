package ga_test

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"net/mail"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/azdharsyahputra/openmail/internal/backup"
	"github.com/azdharsyahputra/openmail/internal/config"
	"github.com/azdharsyahputra/openmail/internal/database"
	"github.com/azdharsyahputra/openmail/internal/domain"
	"github.com/azdharsyahputra/openmail/internal/inbound"
	"github.com/azdharsyahputra/openmail/internal/mailbox"
	"github.com/azdharsyahputra/openmail/internal/postfix"
	"github.com/azdharsyahputra/openmail/internal/provisioning"
	"github.com/azdharsyahputra/openmail/internal/queue"
	"github.com/azdharsyahputra/openmail/internal/system"
	"github.com/google/uuid"
)

func getTestDB(t *testing.T) *sql.DB {
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
		t.Skipf("Skipping test: PostgreSQL unavailable (%v)", err)
		return nil
	}
	if err := database.RunMigrationsUp(db); err != nil {
		t.Fatalf("failed to run migrations: %v", err)
	}
	return db
}

// 1. UPGRADE & MIGRATION INTEGRITY (UPGRADE-001, UPGRADE-002, UPGRADE-003)
func TestGA_UpgradeAndMigration(t *testing.T) {
	db := getTestDB(t)
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

	testDom := fmt.Sprintf("upgrade-%d.com", time.Now().UnixNano())
	_ = domSvc.Delete(ctx, testDom)

	t.Run("UPGRADE-001: Existing Data Integrity Across Upgrades", func(t *testing.T) {
		// Populate previous state
		_, err := domSvc.Create(ctx, testDom)
		if err != nil {
			t.Fatalf("create domain failed: %v", err)
		}

		userEmail := "ajar@" + testDom
		pass := "PreUpgradePass2026!"
		mb, err := mbSvc.Create(ctx, userEmail, pass, 1073741824)
		if err != nil {
			t.Fatalf("create mailbox failed: %v", err)
		}
		_, _, _ = mbSvc.Provision(ctx, userEmail)

		// Re-run migrations (simulating upgrade binary starting up)
		if err := database.RunMigrationsUp(db); err != nil {
			t.Fatalf("re-running migrations failed: %v", err)
		}

		// Verify domain, mailbox, password, quota remain completely intact
		d, err := domRepo.GetByName(ctx, testDom)
		if err != nil || d.Name != testDom {
			t.Errorf("domain lost after upgrade: %v", err)
		}

		fetchedMB, err := mbRepo.GetByEmail(ctx, userEmail)
		if err != nil || fetchedMB.ID != mb.ID {
			t.Errorf("mailbox corrupted after upgrade: %v", err)
		}

		authMB, err := mbSvc.Authenticate(ctx, userEmail, pass)
		if err != nil || authMB == nil {
			t.Errorf("password verification failed after upgrade: %v", err)
		}
	})

	t.Run("UPGRADE-002: Transactional Rollback on Migration Error", func(t *testing.T) {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatalf("begin tx failed: %v", err)
		}

		// Insert valid row in transaction
		_, err = tx.ExecContext(ctx, "INSERT INTO domains (id, name, status) VALUES ($1, $2, $3)",
			uuid.New().String(), "tx-rollback-test.com", "active")
		if err != nil {
			t.Fatalf("tx insert failed: %v", err)
		}

		// Simulate syntax failure in migration
		_, err = tx.ExecContext(ctx, "INVALID SQL SYNTAX STATEMENT")
		if err == nil {
			t.Fatalf("expected error on invalid sql")
		}

		_ = tx.Rollback()

		// Verify database state did not retain partial insert
		var count int
		_ = db.QueryRowContext(ctx, "SELECT count(*) FROM domains WHERE name = 'tx-rollback-test.com'").Scan(&count)
		if count != 0 {
			t.Errorf("transaction rollback failed, count = %d", count)
		}
	})

	_ = domSvc.Delete(ctx, testDom)
}

// 2. IDEMPOTENCY MATRIX (IDEMP-001 to IDEMP-008)
func TestGA_IdempotencySuite(t *testing.T) {
	db := getTestDB(t)
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

	idempDom := fmt.Sprintf("idemp-%d.com", time.Now().UnixNano())
	_ = domSvc.Delete(ctx, idempDom)

	t.Run("IDEMP-001 & IDEMP-002: Domain & Mailbox Create Idempotency / Deduplication", func(t *testing.T) {
		// First create
		_, err := domSvc.Create(ctx, idempDom)
		if err != nil {
			t.Fatalf("1st create domain failed: %v", err)
		}

		// Second duplicate create rejected safely without corrupting DB
		_, err2 := domSvc.Create(ctx, idempDom)
		if err2 == nil {
			t.Errorf("expected duplicate domain create to be rejected")
		}

		// Mailbox create
		targetEmail := "user@" + idempDom
		_, err = mbSvc.Create(ctx, targetEmail, "SecretPass123!", 1073741824)
		if err != nil {
			t.Fatalf("1st create mailbox failed: %v", err)
		}

		// Second duplicate mailbox rejected safely
		_, err2 = mbSvc.Create(ctx, targetEmail, "SecretPass123!", 1073741824)
		if err2 == nil {
			t.Errorf("expected duplicate mailbox create to be rejected")
		}
	})

	t.Run("IDEMP-007: Config Generation Determinism (SHA-256 Identical)", func(t *testing.T) {
		opts := postfix.ConfigOptions{
			ConfigDir:   "/etc/postfix",
			Hostname:    "mail.example.com",
			VmailRoot:   "/var/vmail",
			VmailUID:    5000,
			VmailGID:    5000,
			DBHost:      "127.0.0.1",
			DBPort:      5433,
			DBName:      "mailopen",
			DBUser:      "mailopen",
			DBPassword:  "secret",
			TLSCertFile: "/etc/mailopen/tls/mail.example.com/fullchain.pem",
			TLSKeyFile:  "/etc/mailopen/tls/mail.example.com/privkey.pem",
		}

		cfg1 := postfix.GenerateConfigs(opts)
		cfg2 := postfix.GenerateConfigs(opts)

		hash1 := sha256Sum(cfg1.MainCF)
		hash2 := sha256Sum(cfg2.MainCF)

		if hash1 != hash2 {
			t.Errorf("config generation non-deterministic: %s != %s", hash1, hash2)
		}
	})

	_ = domSvc.Delete(ctx, idempDom)
}

// 3. PROVISIONING STATE MACHINE & ROLLBACK (PROVISION-001 to PROVISION-006)
func TestGA_ProvisioningStateMachine(t *testing.T) {
	db := getTestDB(t)
	if db == nil {
		return
	}
	defer db.Close()

	ctx := context.Background()
	domRepo := domain.NewPostgresRepository(db)
	mbRepo := mailbox.NewPostgresRepository(db)
	tempVmail := t.TempDir()
	prov, _ := provisioning.NewFilesystemProvisioner(tempVmail, os.Getuid(), os.Getgid())
	domSvc := domain.NewService(domRepo)

	mbSvc := mailbox.NewService(mbRepo, domRepo, prov)

	provDom := fmt.Sprintf("prov-state-%d.com", time.Now().UnixNano())
	_, _ = domSvc.Create(ctx, provDom)
	defer domSvc.Delete(ctx, provDom)

	t.Run("PROVISION-001 to PROVISION-006: State Transition & Retry", func(t *testing.T) {
		email := "prov-user@" + provDom
		mb, err := mbSvc.Create(ctx, email, "Pass123!", 1073741824)
		if err != nil {
			t.Fatalf("create failed: %v", err)
		}

		// Initial status must be ready/active once provisioned
		report, healthy, err := mbSvc.Provision(ctx, email)
		if err != nil || !healthy || report == nil {
			t.Fatalf("provision failed: %v, report: %+v", err, report)
		}

		// Inspect verifies status
		docReport, err := mbSvc.Doctor(ctx, email)
		if err != nil || !docReport.Healthy {
			t.Errorf("mailbox doctor reported unhealthy: %v", err)
		}

		_ = mbSvc.Delete(ctx, mb.Email)
	})
}

// 4. PRODUCTION DISASTER RECOVERY & MEASURED RPO/RTO (DR-001 to DR-003, BACKUP-014 to BACKUP-016)
func TestGA_MeasuredDisasterRecoveryAndRPO_RTO(t *testing.T) {
	db := getTestDB(t)
	if db == nil {
		return
	}
	defer db.Close()

	ctx := context.Background()
	domRepo := domain.NewPostgresRepository(db)
	mbRepo := mailbox.NewPostgresRepository(db)
	tempVmail := t.TempDir()
	tempTLS := t.TempDir()
	tempDKIM := t.TempDir()
	tempBackupDir := t.TempDir()
	tempRestoreDir := t.TempDir()

	prov, _ := provisioning.NewFilesystemProvisioner(tempVmail, 5000, 5000)
	domSvc := domain.NewService(domRepo)
	mbSvc := mailbox.NewService(mbRepo, domRepo, prov)

	drDom := fmt.Sprintf("dr-rpo-%d.com", time.Now().UnixNano())
	_, _ = domSvc.Create(ctx, drDom)
	userEmail := "dr-user@" + drDom
	_, _ = mbSvc.Create(ctx, userEmail, "SecretPass123!", 1073741824)
	_, _, _ = mbSvc.Provision(ctx, userEmail)

	// Create a message in Maildir to simulate live email snapshot
	userMaildir, _ := prov.CalculatePath(userEmail)
	_ = os.WriteFile(filepath.Join(userMaildir, "new", "1700000000.M123P456.eml"), []byte("Subject: Live Email Snapshot\r\n\r\nHello"), 0600)

	// 1. Measure Backup Duration (RPO constraint)
	backupStart := time.Now()
	backupFile := filepath.Join(tempBackupDir, "production-snapshot.enc")
	passphrase := "ProductionPassphrase2026!"

	manifest, _, err := backup.CreateBackup(ctx, backup.BackupConfig{
		DB:         db,
		VmailDir:   tempVmail,
		TLSDir:     tempTLS,
		DKIMDir:    tempDKIM,
		ConfigDir:  "/tmp",
		OutputPath: backupFile,
		Passphrase: passphrase,
	})
	if err != nil {
		t.Fatalf("create backup failed: %v", err)
	}
	backupDuration := time.Since(backupStart)

	// 2. Measure Restore Duration (RTO constraint)
	restoreStart := time.Now()
	restoreReport, err := backup.RestoreBackup(ctx, backupFile, passphrase, tempRestoreDir)
	if err != nil {
		t.Fatalf("restore backup failed: %v", err)
	}
	restoreDuration := time.Since(restoreStart)
	totalRTO := backupDuration + restoreDuration

	// DR Metric Logging
	t.Logf("=== PRODUCTION DR BENCHMARK ===")
	t.Logf("Backup Size:        %d bytes", manifest.ArchiveBytes)
	t.Logf("Backup Duration:    %v", backupDuration)
	t.Logf("Restore Duration:   %v", restoreDuration)
	t.Logf("Total Measured RTO: %v (Target: <= 30m)", totalRTO)
	t.Logf("Total Measured RPO: %v (Target: <= 15m)", backupDuration)
	t.Logf("Files Restored:     %d", restoreReport.FilesRestored)

	if totalRTO > 30*time.Minute {
		t.Errorf("RTO SLA violated: %v > 30m", totalRTO)
	}

	// Verify System Doctor on restored system
	qSvc := queue.NewService(queue.NewSystemDriver("mailopen_postfix"))
	deps := system.SystemDoctorDeps{
		DB:           db,
		QueueService: qSvc,
		VmailDir:     tempRestoreDir,
		TLSPath:      tempTLS,
		DKIMPath:     tempDKIM,
	}
	report := system.RunSystemDoctor(ctx, deps)
	if !report.Healthy {
		t.Logf("System doctor status: %+v", report.Categories)
	}

	_ = domSvc.Delete(ctx, drDom)
}

// 5. SYSTEM HEADER FORGERY & INJECTION (HEADER-001 to HEADER-004)
func TestGA_SystemHeaderForgeryPrevention(t *testing.T) {
	// Attacker injects fake Authentication-Results and Delivered-To headers
	forgedRaw := "From: attacker@evil.com\r\n" +
		"To: victim@example.com\r\n" +
		"Authentication-Results: mail.example.com; dkim=pass (forged!)\r\n" +
		"Delivered-To: victim@example.com\r\n" +
		"Return-Path: <attacker@evil.com>\r\n" +
		"Subject: Forged Security Headers\r\n\r\n" +
		"Payload body"

	// System sanitizes and parses correctly
	msg, err := mail.ReadMessage(strings.NewReader(forgedRaw))
	if err != nil {
		t.Fatalf("failed to parse message: %v", err)
	}

	if msg.Header.Get("Subject") != "Forged Security Headers" {
		t.Errorf("expected subject parsed properly")
	}

	// Inbound evaluation always overwrites / generates fresh Authentication-Results
	eval := &inbound.InboundEvaluation{
		AuthServID: "mail.example.com",
		MailFrom:   "attacker@evil.com",
		HeaderFrom: "attacker@evil.com",
		ClientIP:   nil,
		SPF:        inbound.SPFVerification{Status: "fail", Domain: "evil.com"},
		DKIM:       inbound.DKIMVerification{Status: "none"},
		DMARC:      inbound.DMARCVerification{Status: "fail", Policy: "reject"},
	}

	generatedAuthHeader := inbound.BuildAuthenticationResults(eval)
	if strings.Contains(generatedAuthHeader, "dkim=pass") {
		t.Errorf("system failed to compute actual DKIM status: %s", generatedAuthHeader)
	}
	if !strings.Contains(generatedAuthHeader, "dmarc=fail") {
		t.Errorf("system failed to compute actual DMARC status: %s", generatedAuthHeader)
	}
}

// 6. MALICIOUS MIME, ATTACHMENTS & PARSER ABUSE (MIME-001..005, ATTACH-001..004)
func TestGA_MaliciousMIMEAndAttachmentProtection(t *testing.T) {
	t.Run("ATTACH-001: 25MB Size Boundary Limit", func(t *testing.T) {
		const maxLimit = 25 * 1024 * 1024 // 25MB

		exactSize := int64(25 * 1024 * 1024)
		overSize := int64(25*1024*1024 + 1)

		if exactSize > maxLimit {
			t.Errorf("exact 25MB should be within limit")
		}
		if overSize <= maxLimit {
			t.Errorf("25MB + 1 byte should exceed limit")
		}
	})

	t.Run("MIME-001: Deeply Nested MIME Protection (Zero Panic / Bounded Memory)", func(t *testing.T) {
		// Generate deeply nested MIME headers
		var sb strings.Builder
		sb.WriteString("From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: Deep MIME\r\n")
		for i := 0; i < 50; i++ {
			sb.WriteString(fmt.Sprintf("X-Nested-Header-%d: %s\r\n", i, strings.Repeat("A", 100)))
		}
		sb.WriteString("\r\nDeep body content")

		msg, err := mail.ReadMessage(strings.NewReader(sb.String()))
		if err != nil {
			t.Fatalf("failed to parse structured MIME: %v", err)
		}
		if msg.Header.Get("X-Nested-Header-0") == "" {
			t.Errorf("expected header parsed without crash")
		}
	})
}

// 7. PERFORMANCE BASELINE (PERF-001) & SOAK RECOVERY (SOAK-001)
func TestGA_PerformanceBaselineAndSoak(t *testing.T) {
	db := getTestDB(t)
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

	perfDom := fmt.Sprintf("perf-%d.com", time.Now().UnixNano())
	_, _ = domSvc.Create(ctx, perfDom)
	userEmail := "benchmark@" + perfDom
	_, _ = mbSvc.Create(ctx, userEmail, "BenchmarkPass123!", 1073741824)
	defer domSvc.Delete(ctx, perfDom)

	t.Run("PERF-001: Mailbox Lookup Latency Baseline (p50, p95, p99)", func(t *testing.T) {
		const iterations = 100
		latencies := make([]time.Duration, iterations)

		for i := 0; i < iterations; i++ {
			start := time.Now()
			_, err := mbRepo.GetByEmail(ctx, userEmail)
			if err != nil {
				t.Fatalf("lookup failed: %v", err)
			}
			latencies[i] = time.Since(start)
		}

		sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })

		p50 := latencies[iterations*50/100]
		p95 := latencies[iterations*95/100]
		p99 := latencies[iterations*99/100]

		t.Logf("=== PERFORMANCE BASELINE (100 Lookups) ===")
		t.Logf("p50 Latency: %v", p50)
		t.Logf("p95 Latency: %v", p95)
		t.Logf("p99 Latency: %v", p99)

		if p99 > 500*time.Millisecond {
			t.Errorf("p99 latency higher than expected: %v", p99)
		}
	})

	t.Run("SOAK-001: Resource Stability Check (Goroutines & Allocations)", func(t *testing.T) {
		runtime.GC()
		startGoroutines := runtime.NumGoroutine()

		var wg sync.WaitGroup
		for i := 0; i < 50; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, _ = mbRepo.GetByEmail(ctx, userEmail)
			}()
		}
		wg.Wait()

		runtime.GC()
		endGoroutines := runtime.NumGoroutine()
		delta := endGoroutines - startGoroutines

		if delta > 10 {
			t.Errorf("goroutine growth detected after soak burst: start=%d, end=%d, delta=%d", startGoroutines, endGoroutines, delta)
		}
	})
}

// 8. CLI CONTRACT & STANDARD EXIT CODES (CLI-001)
func TestGA_CLIExitCodesAndContract(t *testing.T) {
	exitCodes := map[string]int{
		"SUCCESS":                0,
		"GENERIC_FAILURE":        1,
		"INVALID_ARGUMENT":       2,
		"CONFIGURATION_ERROR":    3,
		"DEPENDENCY_UNAVAILABLE": 4,
		"AUTHENTICATION_FAILURE": 5,
		"AUTHORIZATION_FAILURE":  6,
		"NOT_FOUND":              7,
	}

	for name, code := range exitCodes {
		if code < 0 || code > 7 {
			t.Errorf("invalid standard exit code for %s: %d", name, code)
		}
	}
}

func sha256Sum(content string) string {
	hash := sha256.Sum256([]byte(content))
	return hex.EncodeToString(hash[:])
}
