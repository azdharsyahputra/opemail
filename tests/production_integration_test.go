package tests

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/azdharsyahputra/openmail/internal/audit"

	"github.com/azdharsyahputra/openmail/internal/backup"
	"github.com/azdharsyahputra/openmail/internal/bounce"
	"github.com/azdharsyahputra/openmail/internal/config"
	"github.com/azdharsyahputra/openmail/internal/database"
	"github.com/azdharsyahputra/openmail/internal/domain"
	"github.com/azdharsyahputra/openmail/internal/health"
	"github.com/azdharsyahputra/openmail/internal/mailbox"
	"github.com/azdharsyahputra/openmail/internal/metrics"
	"github.com/azdharsyahputra/openmail/internal/provisioning"
	"github.com/azdharsyahputra/openmail/internal/queue"
	"github.com/azdharsyahputra/openmail/internal/quota"
	"github.com/azdharsyahputra/openmail/internal/system"
	"github.com/google/uuid"
)

func TestIntegration_ProductionHardening(t *testing.T) {
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
		t.Skipf("Skipping production hardening integration test: PostgreSQL unavailable (%v)", err)
		return
	}
	defer db.Close()

	if err := database.RunMigrationsUp(db); err != nil {
		t.Fatalf("failed to run migrations: %v", err)
	}

	tempVmailDir, err := os.MkdirTemp("", "openmail-prod-vmail-*")
	if err != nil {
		t.Fatalf("temp vmail error: %v", err)
	}
	defer os.RemoveAll(tempVmailDir)

	domainRepo := domain.NewPostgresRepository(db)
	mailboxRepo := mailbox.NewPostgresRepository(db)
	prov, err := provisioning.NewFilesystemProvisioner(tempVmailDir, 5000, 5000)
	if err != nil {
		t.Fatalf("provisioner error: %v", err)
	}
	domainSvc := domain.NewService(domainRepo)
	mailboxSvc := mailbox.NewService(mailboxRepo, domainRepo, prov)
	auditRepo := audit.NewPostgresRepository(db)
	auditSvc := audit.NewService(auditRepo)
	quotaSvc := quota.NewService(mailboxRepo, prov)

	testDomain := "prod-hardening.example.com"
	_, _ = domainSvc.Create(ctx, testDomain)

	// 1. Mail Queue Management Matrix
	t.Run("Queue Matrix: Postfix Queue Status & Parser", func(t *testing.T) {
		driver := queue.NewSystemDriver("mailopen_postfix")
		qSvc := queue.NewService(driver)

		summary, err := qSvc.GetStatus(ctx)
		if err != nil {
			t.Fatalf("failed to query live queue: %v", err)
		}
		if summary.Total < 0 {
			t.Errorf("invalid total queue count: %d", summary.Total)
		}

		// Verify parser with mock deferred message
		mockDeferred := `-Queue ID- --Size-- ----Arrival Time---- -Sender/Recipient-------
A82F91       1024 Fri Aug 21 22:01:12  sender@example.com
(host mail.receiver.com[198.51.100.1] said: 451 4.7.1 Try again later)
                                         user@gmail.com
`
		msgs, parsedSummary, err := queue.ParseQueueOutput(mockDeferred)
		if err != nil || len(msgs) != 1 || parsedSummary.Deferred != 1 {
			t.Fatalf("failed to parse deferred queue: %v (len: %d)", err, len(msgs))
		}
		if msgs[0].Status != queue.StatusDeferred || msgs[0].Recipient != "user@gmail.com" {
			t.Errorf("parsed queue mismatch: %+v", msgs[0])
		}
	})

	// 2. Bounce Classification Matrix
	t.Run("Bounce Matrix: Permanent (5xx) vs Temporary (4xx) & Enhanced Status Codes", func(t *testing.T) {
		bounceTests := []struct {
			raw              string
			expectedType     bounce.BounceType
			expectedCategory bounce.BounceCategory
			expectedCode     string
		}{
			{
				raw:              "550 5.1.1 <nobody@example.com>: Recipient address rejected: User unknown in virtual mailbox table",
				expectedType:     bounce.TypePermanent,
				expectedCategory: bounce.CategoryRecipientUnknown,
				expectedCode:     "5.1.1",
			},
			{
				raw:              "552 5.2.2 <inbox@full.com>: Quota exceeded (mailbox is full)",
				expectedType:     bounce.TypePermanent,
				expectedCategory: bounce.CategoryMailboxFull,
				expectedCode:     "5.2.2",
			},
			{
				raw:              "451 4.7.1 Service unavailable - try again later",
				expectedType:     bounce.TypeTemporary,
				expectedCategory: bounce.CategoryTemporaryFailure,
				expectedCode:     "4.7.1",
			},
			{
				raw:              "451 4.4.1 [192.0.2.1] Connection timed out",
				expectedType:     bounce.TypeTemporary,
				expectedCategory: bounce.CategoryConnectionFailure,
				expectedCode:     "4.4.1",
			},
		}

		for _, tc := range bounceTests {
			rep := bounce.ClassifyBounce(tc.raw)
			if rep.Type != tc.expectedType || rep.Category != tc.expectedCategory || rep.EnhancedCode != tc.expectedCode {
				t.Errorf("classification error for %q: got type %s (want %s), category %s (want %s), code %s (want %s)",
					tc.raw, rep.Type, tc.expectedType, rep.Category, tc.expectedCategory, rep.EnhancedCode, tc.expectedCode)
			}
		}
	})

	// 3. Storage Quota Enforcement & Reconciler
	t.Run("Quota Matrix: Thresholds, Inbound Rejection & Disk Reconciler", func(t *testing.T) {
		testEmail := "quota-user@" + testDomain
		_ = mailboxSvc.Delete(ctx, testEmail)
		mb, err := mailboxSvc.Create(ctx, testEmail, "SecretPass123!", 1000) // 1000 bytes quota
		if err != nil {
			t.Fatalf("create mailbox error: %v", err)
		}

		// Initial check -> Under Quota
		canAccept, err := quotaSvc.CheckCanAccept(ctx, testEmail, 500)
		if err != nil || !canAccept {
			t.Fatalf("expected 500 bytes to be accepted under 1000 byte quota, got %t (%v)", canAccept, err)
		}

		// Incoming exceeds quota -> Rejected with 552 5.2.2
		canAccept, err = quotaSvc.CheckCanAccept(ctx, testEmail, 1500)
		if canAccept || err != quota.ErrQuotaExceeded {
			t.Fatalf("expected quota rejection, got %t (%v)", canAccept, err)
		}

		// Simulate delivering files to Maildir on disk
		maildirPath, err := prov.CalculatePath(testEmail)
		if err != nil {
			t.Fatalf("calculate path error: %v", err)
		}
		curDir := filepath.Join(maildirPath, "cur")
		_ = os.MkdirAll(curDir, 0750)
		dummyMsg := make([]byte, 850) // 85% usage
		_ = os.WriteFile(filepath.Join(curDir, "msg.eml"), dummyMsg, 0640)

		// Reconcile disk usage
		qReport, err := quotaSvc.Reconcile(ctx, testEmail)
		if err != nil {
			t.Fatalf("reconcile error: %v", err)
		}
		if qReport.UsedBytes != 850 || qReport.Status != quota.StatusWarning {
			t.Errorf("expected 850 bytes warning, got %d bytes status %s", qReport.UsedBytes, qReport.Status)
		}

		// Verify database counter updated
		updatedMB, _ := mailboxRepo.GetByID(ctx, mb.ID)
		if updatedMB.UsedBytes != 850 {
			t.Errorf("expected DB used_bytes 850, got %d", updatedMB.UsedBytes)
		}
	})

	// 4. Message Events & Audit Trail Matrix
	t.Run("Audit Matrix: Message Events, Message Trace & Admin Activity Log", func(t *testing.T) {
		msgID := uuid.New()
		queueID := "A82F31B"

		// Record message lifecycle events
		_ = auditSvc.RecordMessageEvent(ctx, msgID, queueID, audit.EventReceived, "ok", "Inbound connection accepted")
		_ = auditSvc.RecordMessageEvent(ctx, msgID, queueID, audit.EventQueued, "ok", "Enqueued in Postfix")
		_ = auditSvc.RecordMessageEvent(ctx, msgID, queueID, audit.EventDeliveryAttempt, "pass", "Delivered to Maildir/new")
		_ = auditSvc.RecordMessageEvent(ctx, msgID, queueID, audit.EventDelivered, "pass", "Delivery confirmed")

		// Trace message
		trace, err := auditSvc.TraceMessage(ctx, msgID)
		if err != nil {
			t.Fatalf("trace message error: %v", err)
		}
		if trace.QueueID != queueID || len(trace.Events) != 4 {
			t.Errorf("trace mismatch: queueID %s, events count %d", trace.QueueID, len(trace.Events))
		}

		// Record admin audit log
		adminID := uuid.New()
		err = auditSvc.RecordAudit(ctx, "admin", &adminID, "mailbox.create", "mailbox", &msgID, map[string]string{"email": "audit-test@example.com"})
		if err != nil {
			t.Fatalf("record audit log error: %v", err)
		}

		logs, err := auditSvc.ListAuditLogs(ctx, 10)
		if err != nil || len(logs) == 0 {
			t.Fatalf("list audit logs error: %v (len: %d)", err, len(logs))
		}
		if logs[0].Action != "mailbox.create" {
			t.Errorf("expected mailbox.create action, got %s", logs[0].Action)
		}
	})

	// 5. Observability: Prometheus Metrics & Health Endpoints
	t.Run("Observability Matrix: Prometheus Metrics & Health Endpoints", func(t *testing.T) {
		metrics.DefaultRegistry.MessagesReceivedTotal.Add(5)
		metrics.DefaultRegistry.MessagesDeliveredTotal.Add(4)
		metrics.DefaultRegistry.MessagesDeferredTotal.Add(1)

		rendered := metrics.DefaultRegistry.RenderPrometheus()
		if !strings.Contains(rendered, "messages_received_total 5") || !strings.Contains(rendered, "messages_delivered_total 4") {
			t.Errorf("rendered metrics missing counter tokens:\n%s", rendered)
		}

		// Health Checks
		qSvc := queue.NewService(queue.NewSystemDriver("mailopen_postfix"))
		checker := health.NewChecker(db, qSvc, tempVmailDir, "data/tls", "data/dkim")

		liveResp := checker.Live(ctx)
		if liveResp.Status != "OK" {
			t.Errorf("expected live OK, got %s", liveResp.Status)
		}

		readyResp := checker.Ready(ctx)
		if readyResp.Status == "DOWN" {
			t.Errorf("expected ready UP/OK, got %s", readyResp.Status)
		}

		deepResp := checker.Deep(ctx)
		if deepResp.Status == "DOWN" {
			t.Errorf("expected deep UP/OK, got %s", deepResp.Status)
		}
	})

	// 6. Disaster Recovery: Encrypted Backup & Restore Test
	t.Run("Disaster Recovery Matrix: Encrypted Backup, SHA-256 Checksums, and Disposable Restore", func(t *testing.T) {
		tempSrcDir, err := os.MkdirTemp("", "openmail-dr-src-*")
		if err != nil {
			t.Fatalf("temp src error: %v", err)
		}
		defer os.RemoveAll(tempSrcDir)

		tempDstDir, err := os.MkdirTemp("", "openmail-dr-dst-*")
		if err != nil {
			t.Fatalf("temp dst error: %v", err)
		}
		defer os.RemoveAll(tempDstDir)

		maildir := filepath.Join(tempSrcDir, "maildir")
		dkimdir := filepath.Join(tempSrcDir, "dkim")
		tlsdir := filepath.Join(tempSrcDir, "tls")
		_ = os.MkdirAll(maildir, 0750)
		_ = os.MkdirAll(dkimdir, 0750)
		_ = os.MkdirAll(tlsdir, 0750)

		_ = os.WriteFile(filepath.Join(maildir, "sample.eml"), []byte("Subject: Disaster Recovery Test\n\nContent"), 0640)
		_ = os.WriteFile(filepath.Join(dkimdir, "test.private"), []byte("PRIVATE_KEY_DATA"), 0600)
		_ = os.WriteFile(filepath.Join(tlsdir, "test.crt"), []byte("CERTIFICATE_DATA"), 0644)

		archivePath := filepath.Join(tempSrcDir, "test-backup.tar.gz.enc")
		passphrase := "ProdPassphrase2026!"

		bCfg := backup.BackupConfig{
			DB:         db,
			VmailDir:   maildir,
			DKIMDir:    dkimdir,
			TLSDir:     tlsdir,
			Passphrase: passphrase,
			OutputPath: archivePath,
		}

		manifest, outPath, err := backup.CreateBackup(ctx, bCfg)
		if err != nil {
			t.Fatalf("create backup error: %v", err)
		}
		if !manifest.Encrypted || !manifest.Database || !manifest.Maildir {
			t.Errorf("manifest flags mismatch: %+v", manifest)
		}

		// Verify Checksums & Decryptability
		vReport, err := backup.VerifyBackup(outPath, passphrase)
		if err != nil || !vReport.Valid {
			t.Fatalf("backup verification failed: %v (errors: %v)", err, vReport.Errors)
		}

		// Restore to disposable environment
		res, err := backup.RestoreBackup(ctx, outPath, passphrase, tempDstDir)
		if err != nil {
			t.Fatalf("backup restore failed: %v", err)
		}
		if res.FilesRestored < 3 {
			t.Errorf("expected at least 3 restored files, got %d", res.FilesRestored)
		}

		// Validate restored files
		emlContent, err := os.ReadFile(filepath.Join(tempDstDir, "maildir", "sample.eml"))
		if err != nil || string(emlContent) != "Subject: Disaster Recovery Test\n\nContent" {
			t.Errorf("restored maildir content mismatch: %s (%v)", string(emlContent), err)
		}
		keyContent, err := os.ReadFile(filepath.Join(tempDstDir, "dkim", "test.private"))
		if err != nil || string(keyContent) != "PRIVATE_KEY_DATA" {
			t.Errorf("restored dkim key content mismatch: %s (%v)", string(keyContent), err)
		}
	})

	// 7. Full System Doctor & Configuration Validation
	t.Run("System Doctor & Config Validation Report", func(t *testing.T) {
		qSvc := queue.NewService(queue.NewSystemDriver("mailopen_postfix"))
		deps := system.SystemDoctorDeps{
			DB:           db,
			QueueService: qSvc,
			VmailDir:     tempVmailDir,
			TLSPath:      "data/tls",
			DKIMPath:     "data/dkim",
		}

		docReport := system.RunSystemDoctor(ctx, deps)
		if !docReport.Healthy {
			t.Errorf("expected system doctor report healthy, got false: %+v", docReport)
		}

		cfgReport := system.ValidateAllConfigs(ctx, db, tempVmailDir, "data/tls", "data/dkim")
		if !cfgReport.Valid {
			t.Errorf("expected configuration valid, got false: %+v", cfgReport)
		}
	})
}
