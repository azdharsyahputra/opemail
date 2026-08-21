package recovery_test

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/azdharsyahputra/openmail/internal/backup"
	"github.com/azdharsyahputra/openmail/internal/config"
	"github.com/azdharsyahputra/openmail/internal/database"
	"github.com/azdharsyahputra/openmail/internal/domain"
	"github.com/azdharsyahputra/openmail/internal/mailbox"
	"github.com/azdharsyahputra/openmail/internal/provisioning"
	"github.com/azdharsyahputra/openmail/internal/queue"
	"github.com/azdharsyahputra/openmail/internal/system"
	"github.com/google/uuid"
)

func setupRecoveryTestDB(t *testing.T) *sql.DB {
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
		t.Skipf("Skipping recovery test: PostgreSQL unavailable (%v)", err)
		return nil
	}

	if err := database.RunMigrationsUp(db); err != nil {
		t.Fatalf("failed to run migrations: %v", err)
	}
	return db
}


func TestRecovery_CrashAndDisasterRecovery(t *testing.T) {
	db := setupRecoveryTestDB(t)
	if db == nil {
		return
	}
	defer db.Close()

	ctx := context.Background()
	tempVmail := t.TempDir()
	domRepo := domain.NewPostgresRepository(db)
	mbRepo := mailbox.NewPostgresRepository(db)
	prov, _ := provisioning.NewFilesystemProvisioner(tempVmail, 5000, 5000)
	domSvc := domain.NewService(domRepo)
	mbSvc := mailbox.NewService(mbRepo, domRepo, prov)

	testDomain := fmt.Sprintf("rec-%d.example.com", time.Now().UnixNano())
	_, _ = domSvc.Create(ctx, testDomain)

	// RECOVERY-001 & MAILBOX-010: Provisioning Crash Recovery
	t.Run("RECOVERY-001: Provisioning Crash Recovery", func(t *testing.T) {
		crashEmail := "crashed-user@" + testDomain
		// Simulate mailbox inserted into DB with status='provisioning' (as if process died mid-flight)
		dom, _ := domRepo.GetByName(ctx, testDomain)
		crashedMB := &mailbox.Mailbox{
			ID:                 uuid.New(),
			DomainID:           dom.ID,
			DomainName:         testDomain,
			Email:              crashEmail,
			PasswordHash:       "$argon2id$v=19$m=65536,t=3,p=4$dummyhash",
			QuotaBytes:         1073741824,
			Status:             "active",
			ProvisioningStatus: "provisioning", // stuck in provisioning
		}
		_ = mbRepo.Create(ctx, crashedMB)

		// Run Provision repair
		recoveredMB, alreadyProvisioned, err := mbSvc.Provision(ctx, crashEmail)
		if err != nil {
			t.Fatalf("failed to recover crashed mailbox: %v", err)
		}
		if alreadyProvisioned {
			t.Errorf("expected fresh provisioning on crashed state")
		}
		if recoveredMB.ProvisioningStatus != "ready" {
			t.Errorf("expected status 'ready', got: %s", recoveredMB.ProvisioningStatus)
		}

		// Verify Maildir on disk
		maildirPath, _ := prov.CalculatePath(crashEmail)
		if _, err := os.Stat(filepath.Join(maildirPath, "cur")); os.IsNotExist(err) {
			t.Errorf("expected cur dir to exist after recovery")
		}
	})

	// BACKUP-001 through BACKUP-013: Encrypted Backup, Tampering Rejection & Disaster Recovery
	t.Run("BACKUP-001 to BACKUP-013: Disaster Recovery Boss Fight", func(t *testing.T) {
		tempSrc := t.TempDir()
		tempDst := t.TempDir()

		vmailDir := filepath.Join(tempSrc, "vmail")
		dkimDir := filepath.Join(tempSrc, "dkim")
		tlsDir := filepath.Join(tempSrc, "tls")
		cfgDir := filepath.Join(tempSrc, "config")
		_ = os.MkdirAll(vmailDir, 0750)
		_ = os.MkdirAll(dkimDir, 0750)
		_ = os.MkdirAll(tlsDir, 0750)
		_ = os.MkdirAll(cfgDir, 0750)

		_ = os.WriteFile(filepath.Join(vmailDir, "mail.eml"), []byte("Message Body Content"), 0640)
		_ = os.WriteFile(filepath.Join(dkimDir, "selector.private"), []byte("DKIM_PRIVATE_KEY"), 0600)
		_ = os.WriteFile(filepath.Join(tlsDir, "fullchain.pem"), []byte("TLS_CERTIFICATE"), 0644)
		_ = os.WriteFile(filepath.Join(cfgDir, "main.cf"), []byte("myhostname = mail.example.com"), 0644)

		archivePath := filepath.Join(tempSrc, "disaster-backup.tar.gz.enc")
		passphrase := "DisasterBossFightPass2026!"

		bCfg := backup.BackupConfig{
			DB:         db,
			VmailDir:   vmailDir,
			DKIMDir:    dkimDir,
			TLSDir:     tlsDir,
			ConfigDir:  cfgDir,
			Passphrase: passphrase,
			OutputPath: archivePath,
		}

		// 1. Create Backup
		manifest, _, err := backup.CreateBackup(ctx, bCfg)
		if err != nil {
			t.Fatalf("create backup failed: %v", err)
		}
		if !manifest.Encrypted || !manifest.Database {
			t.Errorf("manifest missing encrypted/database flags")
		}

		// BACKUP-002: Wrong passphrase rejected
		vReportWrong, err := backup.VerifyBackup(archivePath, "WrongPassphrase123!")
		if err == nil && (vReportWrong != nil && vReportWrong.Valid) {
			t.Errorf("expected wrong passphrase to be rejected")
		}

		// BACKUP-003: Corrupt ciphertext rejected
		corruptPath := filepath.Join(tempSrc, "corrupt-backup.tar.gz.enc")
		origBytes, _ := os.ReadFile(archivePath)
		corruptBytes := make([]byte, len(origBytes))
		copy(corruptBytes, origBytes)
		corruptBytes[len(corruptBytes)/2] ^= 0xFF // Flip byte
		_ = os.WriteFile(corruptPath, corruptBytes, 0644)

		vReportCorrupt, err := backup.VerifyBackup(corruptPath, passphrase)
		if err == nil && (vReportCorrupt != nil && vReportCorrupt.Valid) {
			t.Errorf("expected corrupted ciphertext to fail integrity verification")
		}

		// BACKUP-005: Truncated backup rejected
		truncPath := filepath.Join(tempSrc, "trunc-backup.tar.gz.enc")
		_ = os.WriteFile(truncPath, origBytes[:len(origBytes)/2], 0644)
		vReportTrunc, err := backup.VerifyBackup(truncPath, passphrase)
		if err == nil && (vReportTrunc != nil && vReportTrunc.Valid) {
			t.Errorf("expected truncated backup to be rejected")
		}

		// 2. Restore into Empty Environment
		res, err := backup.RestoreBackup(ctx, archivePath, passphrase, tempDst)
		if err != nil {
			t.Fatalf("restore failed: %v", err)
		}
		if res.FilesRestored < 4 {
			t.Errorf("expected at least 4 files restored, got: %d", res.FilesRestored)
		}

		// Verify Restored Artifacts
		restoredMail, _ := os.ReadFile(filepath.Join(tempDst, "maildir", "mail.eml"))
		if string(restoredMail) != "Message Body Content" {
			t.Errorf("restored mail content mismatch: %s", string(restoredMail))
		}
		restoredKey, _ := os.ReadFile(filepath.Join(tempDst, "dkim", "selector.private"))
		if string(restoredKey) != "DKIM_PRIVATE_KEY" {
			t.Errorf("restored dkim key mismatch: %s", string(restoredKey))
		}

		// Run System Doctor on restored environment
		qSvc := queue.NewService(queue.NewSystemDriver("mailopen_postfix"))
		docReport := system.RunSystemDoctor(ctx, system.SystemDoctorDeps{
			DB:           db,
			QueueService: qSvc,
			VmailDir:     filepath.Join(tempDst, "maildir"),
			TLSPath:      filepath.Join(tempDst, "tls"),
			DKIMPath:     filepath.Join(tempDst, "dkim"),
		})

		if !docReport.Healthy {
			t.Errorf("expected restored system doctor to be HEALTHY")
		}
	})
}

