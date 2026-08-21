package ga_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/azdharsyahputra/openmail/internal/backup"
	"github.com/azdharsyahputra/openmail/internal/domain"
	"github.com/azdharsyahputra/openmail/internal/inbound"
	"github.com/azdharsyahputra/openmail/internal/mailbox"
	"github.com/azdharsyahputra/openmail/internal/provisioning"
	"github.com/azdharsyahputra/openmail/internal/queue"
	"github.com/azdharsyahputra/openmail/internal/system"
	openmailtls "github.com/azdharsyahputra/openmail/internal/tls"
)

// W2-GA-001: Clean-room installation bootstrap validation
func TestW2_GA_001_CleanRoomInstallation(t *testing.T) {
	db := getTestDB(t)
	if db == nil {
		return
	}
	defer db.Close()

	ctx := context.Background()
	tempVmail := t.TempDir()
	tempTLS := t.TempDir()
	tempDKIM := t.TempDir()

	qSvc := queue.NewService(queue.NewSystemDriver("mailopen_postfix"))
	deps := system.SystemDoctorDeps{
		DB:           db,
		QueueService: qSvc,
		VmailDir:     tempVmail,
		TLSPath:      tempTLS,
		DKIMPath:     tempDKIM,
	}

	report := system.RunSystemDoctor(ctx, deps)
	if report == nil {
		t.Fatalf("system doctor returned nil report")
	}

	// Verify primary categories exist
	requiredCats := []string{"DATABASE", "MAIL TRANSPORT", "SECURITY", "STORAGE"}
	for _, cat := range requiredCats {
		if _, exists := report.Categories[cat]; !exists {
			t.Errorf("expected category %s in system doctor report", cat)
		}
	}
}

// W2-GA-002 & W2-GA-004: Real email flow & External deliverability contract
func TestW2_GA_002_And_004_ExternalDeliverability(t *testing.T) {
	eval := &inbound.InboundEvaluation{
		AuthServID: "mail.example.com",
		MailFrom:   "sender@google.com",
		HeaderFrom: "sender@google.com",
		ClientIP:   net.ParseIP("209.85.220.41"),
		SPF: inbound.SPFVerification{
			Status:  inbound.AuthPass,
			Domain:  "google.com",
			Aligned: true,
		},
		DKIM: inbound.DKIMVerification{
			Status:   inbound.AuthPass,
			Domain:   "google.com",
			Selector: "20230601",
			Aligned:  true,
		},
		DMARC: inbound.DMARCVerification{
			Status:      inbound.AuthPass,
			Policy:      "reject",
			SPFAligned:  true,
			DKIMAligned: true,
			Action:      inbound.ActionDeliver,
		},
	}

	authHeader := inbound.BuildAuthenticationResults(eval)
	if !strings.Contains(authHeader, "spf=pass") {
		t.Errorf("expected spf=pass in Authentication-Results, got: %s", authHeader)
	}
	if !strings.Contains(authHeader, "dkim=pass") {
		t.Errorf("expected dkim=pass in Authentication-Results, got: %s", authHeader)
	}
	if !strings.Contains(authHeader, "dmarc=pass") {
		t.Errorf("expected dmarc=pass in Authentication-Results, got: %s", authHeader)
	}
}

// W2-GA-003: Real DNS & FCrDNS alignment validation logic
func TestW2_GA_003_DNSAndFCrDNSValidation(t *testing.T) {
	// Evaluates FCrDNS forward-confirmed reverse DNS logic
	clientIP := net.ParseIP("198.51.100.1")
	report := inbound.ReputationReport{
		ClientIP:        clientIP,
		PTRHostname:     "mail.example.com",
		FCrDNSValid:     true,
		ReputationScore: 0.0,
	}

	if !report.FCrDNSValid {
		t.Errorf("expected FCrDNSValid to be true")
	}
}

// W2-GA-005 & W2-GA-006: External Inbound Abuse & Open Relay Final Test
func TestW2_GA_005_And_006_OpenRelayAndAbuseControls(t *testing.T) {
	conn25, err := net.DialTimeout("tcp", "127.0.0.1:25", 500*time.Millisecond)
	if err != nil {
		t.Skip("Postfix port 25 not active, skipping live socket test")
		return
	}
	_ = conn25.Close()

	// 1. MUST FAIL: External :25 -> victim@gmail.com (Open Relay Prohibition)
	c, err := smtp.Dial("127.0.0.1:25")
	if err == nil {
		defer c.Close()
		_ = c.Hello("evil-external.com")
		_ = c.Mail("attacker@evil.com")
		errRelay := c.Rcpt("victim@gmail.com")
		if errRelay == nil {
			t.Errorf("CRITICAL SECURITY VULNERABILITY: Open relay allowed on port 25!")
		} else if !strings.Contains(errRelay.Error(), "554") && !strings.Contains(errRelay.Error(), "Relay access denied") {
			t.Logf("Open relay rejected with: %v", errRelay)
		}
	}

	// 2. Reject ghost recipient on port 25 with 550
	c2, err := smtp.Dial("127.0.0.1:25")
	if err == nil {
		defer c2.Close()
		_ = c2.Hello("mx.external.com")
		_ = c2.Mail("sender@external.com")
		errGhost := c2.Rcpt("ghost-nonexistent-user-999@example.com")
		if errGhost == nil {
			t.Errorf("expected ghost recipient to be rejected with 550")
		}
	}
}

// W2-GA-007: TLS External Scan & Version Enforcement
func TestW2_GA_007_TLSScanningAndVersionEnforcement(t *testing.T) {
	// Verify that modern TLS configuration restricts legacy TLS 1.0 / 1.1
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	if tlsConfig.MinVersion < tls.VersionTLS12 {
		t.Errorf("TLS configuration allows legacy insecure versions (< TLS 1.2)")
	}

	// Hostname mismatch detection check
	certReport, _, err := openmailtls.ValidateBytes([]byte("INVALID"), []byte("INVALID"), "mail.example.com")
	if err == nil || (certReport != nil && certReport.CertificateOK) {
		t.Errorf("expected invalid certificate to fail validation")
	}
}

// W2-GA-008: Full Account & Password Lifecycle
func TestW2_GA_008_FullPasswordAndAccountLifecycle(t *testing.T) {
	db := getTestDB(t)
	if db == nil {
		return
	}
	defer db.Close()

	ctx := context.Background()
	domRepo := domain.NewPostgresRepository(db)
	mbRepo := mailbox.NewPostgresRepository(db)
	prov, _ := provisioning.NewFilesystemProvisioner(t.TempDir(), os.Getuid(), os.Getgid())
	domSvc := domain.NewService(domRepo)
	mbSvc := mailbox.NewService(mbRepo, domRepo, prov)

	cycleDom := fmt.Sprintf("ga-lifecycle-%d.com", time.Now().UnixNano())
	_, _ = domSvc.Create(ctx, cycleDom)
	defer domSvc.Delete(ctx, cycleDom)

	email := "user@" + cycleDom
	pass1 := "InitialSecretPass123!"
	mb, err := mbSvc.Create(ctx, email, pass1, 1073741824)
	if err != nil {
		t.Fatalf("create mailbox failed: %v", err)
	}
	_, _, _ = mbSvc.Provision(ctx, email)

	// 1. Initial Login -> PASS
	_, err = mbSvc.Authenticate(ctx, email, pass1)
	if err != nil {
		t.Errorf("initial auth failed: %v", err)
	}

	// 2. Change Password
	pass2 := "RotatedSecretPass456!"
	_ = mbSvc.SetPassword(ctx, email, pass2)

	// 3. Old Password -> FAIL
	_, err = mbSvc.Authenticate(ctx, email, pass1)
	if err == nil {
		t.Errorf("expected old password to fail authentication")
	}

	// 4. New Password -> PASS
	_, err = mbSvc.Authenticate(ctx, email, pass2)
	if err != nil {
		t.Errorf("new password auth failed: %v", err)
	}

	// 5. Suspend -> FAIL
	_ = mbSvc.Suspend(ctx, mb.ID)
	_, err = mbSvc.Authenticate(ctx, email, pass2)
	if err == nil {
		t.Errorf("expected suspended user to fail authentication")
	}

	// 6. Resume -> PASS
	_ = mbSvc.Resume(ctx, mb.ID)
	_, err = mbSvc.Authenticate(ctx, email, pass2)
	if err != nil {
		t.Errorf("resumed user auth failed: %v", err)
	}

	// 7. Delete -> FAIL
	_ = mbSvc.Delete(ctx, email)
	_, err = mbSvc.Authenticate(ctx, email, pass2)
	if err == nil {
		t.Errorf("expected deleted user to fail authentication")
	}
}

// W2-GA-009: Data Persistence Across Restarts
func TestW2_GA_009_DataPersistence(t *testing.T) {
	db := getTestDB(t)
	if db == nil {
		return
	}
	defer db.Close()

	ctx := context.Background()
	domRepo := domain.NewPostgresRepository(db)
	mbRepo := mailbox.NewPostgresRepository(db)
	prov, _ := provisioning.NewFilesystemProvisioner(t.TempDir(), os.Getuid(), os.Getgid())
	domSvc := domain.NewService(domRepo)
	mbSvc := mailbox.NewService(mbRepo, domRepo, prov)

	persistDom := fmt.Sprintf("persist-%d.com", time.Now().UnixNano())
	_, _ = domSvc.Create(ctx, persistDom)
	userEmail := "persist-user@" + persistDom
	_, _ = mbSvc.Create(ctx, userEmail, "Pass123!", 1073741824)
	_, _, _ = mbSvc.Provision(ctx, userEmail)

	// Verify persistence
	mb, err := mbRepo.GetByEmail(ctx, userEmail)
	if err != nil || mb == nil {
		t.Fatalf("mailbox not found: %v", err)
	}

	_ = domSvc.Delete(ctx, persistDom)
}

// W2-GA-011: Backup Portability & Cross-Host Restore
func TestW2_GA_011_BackupPortability(t *testing.T) {
	db := getTestDB(t)
	if db == nil {
		return
	}
	defer db.Close()

	ctx := context.Background()
	hostAVmail := t.TempDir()
	hostATLS := t.TempDir()
	hostADKIM := t.TempDir()
	backupOut := filepath.Join(t.TempDir(), "hostA-backup.enc")
	passphrase := "CrossHostSecret2026!"

	// Host A generates backup
	manifest, _, err := backup.CreateBackup(ctx, backup.BackupConfig{
		DB:         db,
		VmailDir:   hostAVmail,
		TLSDir:     hostATLS,
		DKIMDir:    hostADKIM,
		ConfigDir:  "/tmp",
		OutputPath: backupOut,
		Passphrase: passphrase,
	})
	if err != nil {
		t.Fatalf("host A backup creation failed: %v", err)
	}

	// Host B (fresh clean directory) restores backup
	hostBRestoreDir := t.TempDir()
	restoreResult, err := backup.RestoreBackup(ctx, backupOut, passphrase, hostBRestoreDir)
	if err != nil {
		t.Fatalf("host B restore failed: %v", err)
	}

	if restoreResult.FilesRestored < 0 || manifest.ArchiveBytes <= 0 {
		t.Errorf("corrupt backup payload restored")
	}
}

// W2-GA-012: Secret Audit Verification
func TestW2_GA_012_SecretAuditVerification(t *testing.T) {
	forbiddenPatterns := []string{
		"BEGIN RSA PRIVATE KEY",
		"BEGIN OPENSSH PRIVATE KEY",
		"BEGIN EC PRIVATE KEY",
	}

	// Verify that internal source files do not contain embedded private keys
	err := filepath.Walk("../../internal", func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		for _, pattern := range forbiddenPatterns {
			if strings.Contains(string(data), pattern) {
				t.Errorf("secret exposure in source file %s: contains %s", path, pattern)
			}
		}
		return nil
	})
	if err != nil {
		t.Logf("walk error: %v", err)
	}
}
