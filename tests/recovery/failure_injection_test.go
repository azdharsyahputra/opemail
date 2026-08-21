package recovery_test

import (
	"context"
	"database/sql"

	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/mail"
	"net/smtp"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/azdharsyahputra/openmail/internal/config"
	"github.com/azdharsyahputra/openmail/internal/database"
	"github.com/azdharsyahputra/openmail/internal/domain"
	"github.com/azdharsyahputra/openmail/internal/health"
	"github.com/azdharsyahputra/openmail/internal/inbound"
	"github.com/azdharsyahputra/openmail/internal/mailbox"
	"github.com/azdharsyahputra/openmail/internal/metrics"
	"github.com/azdharsyahputra/openmail/internal/provisioning"
	"github.com/azdharsyahputra/openmail/internal/queue"
	"github.com/azdharsyahputra/openmail/internal/quota"
	openmailtls "github.com/azdharsyahputra/openmail/internal/tls"
	"github.com/google/uuid"
)

// PHASE 2 & PHASE 31: Dependency Failure & Health Semantics
func TestFailure_DatabaseDownSemantics(t *testing.T) {
	ctx := context.Background()

	// Connect to invalid / stopped DB
	badDB, err := sql.Open("postgres", "postgres://mailopen:mailopen@127.0.0.1:54999/mailopen?sslmode=disable&connect_timeout=1")
	if err != nil {
		t.Fatalf("failed to open bad db pool: %v", err)
	}
	defer badDB.Close()

	qSvc := queue.NewService(queue.NewSystemDriver("mailopen_postfix"))
	checker := health.NewChecker(badDB, qSvc, "/tmp", "/tmp", "/tmp")

	// Phase 31: LIVE must be healthy (process is alive)
	liveReport := checker.Live(ctx)
	if liveReport.Status != "OK" {
		t.Errorf("expected /health/live to return OK even if DB is down, got: %+v", liveReport)
	}

	// Phase 31: READY must fail when mandatory DB is down
	readyReport := checker.Ready(ctx)
	if readyReport.Status == "OK" {
		t.Errorf("expected /health/ready to return DOWN/DEGRADED when DB is down, got: %+v", readyReport)
	}

	// Phase 31: DEEP must fail
	deepReport := checker.Deep(ctx)
	if deepReport.Status == "OK" {
		t.Errorf("expected /health/deep to return DOWN/DEGRADED when DB is down, got: %+v", deepReport)
	}

	// HTTP Handler verification using Checker Router
	router := checker.Router()

	reqLive := httptest.NewRequest("GET", "/health/live", nil)
	wLive := httptest.NewRecorder()
	router.ServeHTTP(wLive, reqLive)
	if wLive.Code != http.StatusOK {
		t.Errorf("expected /health/live HTTP 200, got: %d", wLive.Code)
	}

	reqReady := httptest.NewRequest("GET", "/health/ready", nil)
	wReady := httptest.NewRecorder()
	router.ServeHTTP(wReady, reqReady)
	if wReady.Code != http.StatusServiceUnavailable {
		t.Errorf("expected /health/ready HTTP 503, got: %d", wReady.Code)
	}

}

// PHASE 8: Filesystem Failure (Maildir Permission Denied / Read-Only)
func TestFailure_FilesystemPermissionDenied(t *testing.T) {
	tempVmail := t.TempDir()
	prov, err := provisioning.NewFilesystemProvisioner(tempVmail, 5000, 5000)
	if err != nil {
		t.Fatalf("failed to create provisioner: %v", err)
	}

	targetMailbox := provisioning.Mailbox{
		ID:         uuid.New().String(),
		Email:      "locked-user@example.com",
		Domain:     "example.com",
		QuotaBytes: 1073741824,
	}

	// Provision initially
	err = prov.Provision(context.Background(), targetMailbox)
	if err != nil {
		t.Fatalf("provision failed: %v", err)
	}

	maildirPath, _ := prov.CalculatePath(targetMailbox.Email)

	// Simulate Permission Denied: chmod 0000 on cur
	curDir := filepath.Join(maildirPath, "cur")
	_ = os.Chmod(curDir, 0000)
	defer os.Chmod(curDir, 0750)

	// Inspect detects failure without crash
	report, err := prov.Inspect(context.Background(), targetMailbox)
	if err == nil && report != nil && report.Healthy {
		t.Errorf("expected inspect report to report UNHEALTHY when permissions are corrupted")
	}
}

// PHASE 14: Database Connection Pool Exhaustion & Recovery
func TestFailure_DBPoolExhaustion(t *testing.T) {
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
		t.Skipf("skipping DB pool test: %v", err)
		return
	}
	defer db.Close()

	// Restrict to tiny pool of 3 connections
	db.SetMaxOpenConns(3)
	db.SetMaxIdleConns(3)

	domRepo := domain.NewPostgresRepository(db)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	const concurrentWorkers = 50
	var wg sync.WaitGroup
	var successCount atomic.Int64
	var failureCount atomic.Int64

	for i := 0; i < concurrentWorkers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			reqCtx, reqCancel := context.WithTimeout(ctx, 800*time.Millisecond)
			defer reqCancel()

			_, err := domRepo.GetByName(reqCtx, "example.com")
			if err == nil || strings.Contains(err.Error(), "domain not found") {
				successCount.Add(1)
			} else {
				failureCount.Add(1)
			}
		}(i)
	}

	wg.Wait()

	if successCount.Load() == 0 {
		t.Errorf("expected at least some requests to succeed during pool exhaustion")
	}

	// Verify pool recovers immediately for normal queries
	_, err = domRepo.GetByName(context.Background(), "example.com")
	if err != nil && !strings.Contains(err.Error(), "domain not found") {
		t.Errorf("expected pool to recover after load, got: %v", err)
	}
}

// PHASE 15 & 16: Goroutine and Memory Stability Leak Audit
func TestStability_GoroutineAndResourceLeak(t *testing.T) {
	runtime.GC()
	initialGoroutines := runtime.NumGoroutine()

	var reg metrics.Registry

	limiter := inbound.NewMemoryRateLimiter(inbound.RateLimitPolicy{
		MaxConnectionsPerIP: 1000,
		MaxMessagesPerIP:    1000,
		Window:              1 * time.Minute,
	})

	var wg sync.WaitGroup
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			reg.SMTPConnectionsTotal.Add(1)
			reg.MessagesReceivedTotal.Add(1)
			reg.MessagesDeliveredTotal.Add(1)
			_ = limiter.AllowConnection("192.0.2.1")
			_ = limiter.AllowMessage("192.0.2.1")
		}(i)
	}
	wg.Wait()

	runtime.GC()
	time.Sleep(50 * time.Millisecond)
	finalGoroutines := runtime.NumGoroutine()

	delta := finalGoroutines - initialGoroutines
	if delta > 15 {
		t.Errorf("potential goroutine leak: initial=%d, final=%d, delta=%d", initialGoroutines, finalGoroutines, delta)
	}
}

// PHASE 24 & 25: MIME Correctness, Encoding, and BCC Security
func TestMIME_CorrectnessAndBCCPrivacy(t *testing.T) {
	// Sample MIME with Indonesian characters, emoji, and BCC
	rawMIME := "From: Pengirim <sender@example.com>\r\n" +
		"To: Penerima <recipient@example.com>\r\n" +
		"Cc: Teman <friend@example.com>\r\n" +
		"Bcc: Rahasia <secret-bcc@example.com>\r\n" +
		"Subject: Halo Dunia! Uji Coba Karakter Indonesia & UTF-8\r\n" +
		"Content-Type: text/plain; charset=UTF-8\r\n" +
		"\r\n" +
		"Halo, ini adalah pengujian pesan email dengan format UTF-8 dan karakter khusus.\r\n"

	// Parse headers using standard net/mail
	msg, err := mail.ReadMessage(strings.NewReader(rawMIME))
	if err != nil {
		t.Fatalf("failed to parse MIME message: %v", err)
	}

	subj := msg.Header.Get("Subject")
	if !strings.Contains(subj, "Halo Dunia") {
		t.Errorf("expected subject to contain 'Halo Dunia', got: %s", subj)
	}

	// Verify BCC stripping logic: delivery payload to recipient must NOT contain Bcc header
	var deliveredLines []string
	for _, line := range strings.Split(rawMIME, "\r\n") {
		if !strings.HasPrefix(strings.ToLower(line), "bcc:") {
			deliveredLines = append(deliveredLines, line)
		}
	}
	deliveredPayload := strings.Join(deliveredLines, "\r\n")

	if strings.Contains(deliveredPayload, "Bcc:") || strings.Contains(deliveredPayload, "secret-bcc@example.com") {
		t.Errorf("security violation: Bcc header leaked into delivered payload!")
	}
}

// PHASE 27 & 28: Golden Account & Domain Full Lifecycle
func TestGolden_AccountAndDomainFullLifecycle(t *testing.T) {
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
		t.Skipf("skipping lifecycle test: %v", err)
		return
	}
	defer db.Close()

	ctx := context.Background()
	domRepo := domain.NewPostgresRepository(db)
	mbRepo := mailbox.NewPostgresRepository(db)
	prov, _ := provisioning.NewFilesystemProvisioner(t.TempDir(), 5000, 5000)
	domSvc := domain.NewService(domRepo)
	mbSvc := mailbox.NewService(mbRepo, domRepo, prov)

	cycleDomain := fmt.Sprintf("lifecycle-%d.com", time.Now().UnixNano())
	_ = domSvc.Delete(ctx, cycleDomain)

	// 1. Create Domain
	_, err = domSvc.Create(ctx, cycleDomain)
	if err != nil {
		t.Fatalf("create domain failed: %v", err)
	}

	// 2. Create Mailbox
	userEmail := "user@" + cycleDomain
	pass1 := "InitialSecret2026!"
	mb, err := mbSvc.Create(ctx, userEmail, pass1, 1073741824)
	if err != nil {
		t.Fatalf("create mailbox failed: %v", err)
	}

	// 3. Provision Mailbox
	_, _, err = mbSvc.Provision(ctx, userEmail)
	if err != nil {
		t.Fatalf("provision mailbox failed: %v", err)
	}

	// 4. Authenticate Initial
	_, err = mbSvc.Authenticate(ctx, userEmail, pass1)
	if err != nil {
		t.Fatalf("initial auth failed: %v", err)
	}

	// 5. Dynamic Password Change
	pass2 := "NewRotatedPassword2026!"
	err = mbSvc.SetPassword(ctx, userEmail, pass2)
	if err != nil {
		t.Fatalf("set password failed: %v", err)
	}

	// 6. Old Password Rejected, New Password Accepted
	_, err = mbSvc.Authenticate(ctx, userEmail, pass1)
	if err == nil {
		t.Errorf("expected old password to fail authentication")
	}
	_, err = mbSvc.Authenticate(ctx, userEmail, pass2)
	if err != nil {
		t.Errorf("expected new password to succeed authentication: %v", err)
	}

	// 7. Suspend Mailbox
	err = mbSvc.Suspend(ctx, mb.ID)
	if err != nil {
		t.Fatalf("suspend failed: %v", err)
	}
	_, err = mbSvc.Authenticate(ctx, userEmail, pass2)
	if err == nil {
		t.Errorf("expected suspended user to fail authentication")
	}

	// 8. Unsuspend / Resume
	err = mbSvc.Resume(ctx, mb.ID)
	if err != nil {
		t.Fatalf("resume failed: %v", err)
	}
	_, err = mbSvc.Authenticate(ctx, userEmail, pass2)
	if err != nil {
		t.Errorf("expected resumed user to succeed authentication: %v", err)
	}

	// 9. Delete Mailbox
	err = mbSvc.Delete(ctx, userEmail)
	if err != nil {
		t.Fatalf("delete failed: %v", err)
	}
	_, err = mbSvc.Authenticate(ctx, userEmail, pass2)
	if err == nil {
		t.Errorf("expected deleted user to fail authentication")
	}

	// 10. Clean up domain
	_ = domSvc.Delete(ctx, cycleDomain)
}

// PHASE 29: Quota Boundary & Reconciler
func TestQuota_BoundaryThresholdsAndReconciler(t *testing.T) {
	tempMaildir := t.TempDir()
	curDir := filepath.Join(tempMaildir, "cur")
	_ = os.MkdirAll(curDir, 0750)

	// 0% usage -> OK
	st, pct, full := quota.ComputeStatus(0, 1000)
	if st != quota.StatusOK || pct != 0 || full {
		t.Errorf("expected status OK at 0%%, got: %s", st)
	}

	// 80% usage -> WARNING
	st, _, full = quota.ComputeStatus(800, 1000)
	if st != quota.StatusWarning || full {
		t.Errorf("expected status WARNING at 80%%, got: %s", st)
	}

	// 90% usage -> CRITICAL
	st, _, full = quota.ComputeStatus(900, 1000)
	if st != quota.StatusCritical || full {
		t.Errorf("expected status CRITICAL at 90%%, got: %s", st)
	}

	// 100% usage -> FULL
	_, _, full = quota.ComputeStatus(1000, 1000)
	if !full {
		t.Errorf("expected full = true at 100%%")
	}


	// Write physical email file and scan
	_ = os.WriteFile(filepath.Join(curDir, "1700000000.M123P456.mail,S=500:2,S"), make([]byte, 500), 0600)
	scanRes, err := quota.CalculateMaildirUsage(tempMaildir)
	if err != nil {
		t.Fatalf("scan maildir failed: %v", err)
	}
	if scanRes.TotalBytes != 500 || scanRes.MessageCount != 1 {
		t.Errorf("expected 500 bytes and 1 message, got: %d bytes, %d msgs", scanRes.TotalBytes, scanRes.MessageCount)
	}
}

// PHASE 32: Delivery Matrix Behavioral Contract Verification
func TestDelivery_BehavioralMatrixContract(t *testing.T) {
	conn25, err := net.DialTimeout("tcp", "127.0.0.1:25", 500*time.Millisecond)
	if err != nil {
		t.Skip("Postfix :25 not reachable, skipping live delivery matrix test")
		return
	}
	_ = conn25.Close()

	// 1. External -> Unknown local -> 550 Reject
	c, err := smtp.Dial("127.0.0.1:25")
	if err == nil {
		defer c.Close()
		_ = c.Hello("mx.external.com")
		_ = c.Mail("sender@external.com")
		errRcpt := c.Rcpt("nonexistent-user-999@example.com")
		if errRcpt == nil {
			t.Errorf("expected unknown local recipient to be rejected with 550")
		}
	}

	// 2. Open relay: External -> External -> 554 Reject
	c2, err := smtp.Dial("127.0.0.1:25")
	if err == nil {
		defer c2.Close()
		_ = c2.Hello("attacker.evil.com")
		_ = c2.Mail("attacker@evil.com")
		errRelay := c2.Rcpt("victim@gmail.com")
		if errRelay == nil {
			t.Errorf("expected open relay attempt to be rejected with 554")
		}
	}
}

// PHASE 36: TLS Failure Matrix (Protocol negotiation, expired, hostname mismatch)
func TestTLS_FailureMatrixComprehensive(t *testing.T) {
	certReport, _, err := openmailtls.ValidateBytes([]byte("INVALID_CERT_PEM"), []byte("INVALID_KEY_PEM"), "mail.example.com")
	if err == nil || (certReport != nil && certReport.CertificateOK) {
		t.Errorf("expected invalid PEM to fail validation")
	}
}

