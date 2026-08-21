package backup_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/azdharsyahputra/openmail/internal/backup"
)

func TestBackupEncryptedVerifyAndRestore(t *testing.T) {
	tempSrcDir, err := os.MkdirTemp("", "openmail-backup-src-*")
	if err != nil {
		t.Fatalf("temp src dir error: %v", err)
	}
	defer os.RemoveAll(tempSrcDir)

	// Create dummy test files
	maildir := filepath.Join(tempSrcDir, "maildir")
	dkimdir := filepath.Join(tempSrcDir, "dkim")
	tlsdir := filepath.Join(tempSrcDir, "tls")
	_ = os.MkdirAll(maildir, 0750)
	_ = os.MkdirAll(dkimdir, 0750)
	_ = os.MkdirAll(tlsdir, 0750)

	_ = os.WriteFile(filepath.Join(maildir, "msg1.eml"), []byte("From: alice@test.com\n\nSecret Email"), 0640)
	_ = os.WriteFile(filepath.Join(dkimdir, "mailopen.private"), []byte("-----BEGIN PRIVATE KEY-----\nMOCK_KEY\n-----END PRIVATE KEY-----"), 0600)
	_ = os.WriteFile(filepath.Join(tlsdir, "fullchain.pem"), []byte("-----BEGIN CERTIFICATE-----\nMOCK_CERT\n-----END CERTIFICATE-----"), 0644)

	backupFile := filepath.Join(tempSrcDir, "test-backup.tar.gz.enc")
	passphrase := "StrongBackupPassphrase2026!"

	ctx := context.Background()
	cfg := backup.BackupConfig{
		VmailDir:   maildir,
		DKIMDir:    dkimdir,
		TLSDir:     tlsdir,
		Passphrase: passphrase,
		OutputPath: backupFile,
	}

	// 1. Create Encrypted Backup
	manifest, outPath, err := backup.CreateBackup(ctx, cfg)
	if err != nil {
		t.Fatalf("create backup failed: %v", err)
	}
	if !manifest.Encrypted || !manifest.Maildir || !manifest.DKIM || !manifest.TLS {
		t.Errorf("manifest flags mismatch: %+v", manifest)
	}

	// 2. Verify with wrong passphrase -> Must Fail
	repWrong, err := backup.VerifyBackup(outPath, "WrongPassword!")
	if err != nil {
		t.Fatalf("verify error: %v", err)
	}
	if repWrong.Valid {
		t.Errorf("expected verification with wrong password to fail")
	}

	// 3. Verify with correct passphrase -> Must Pass
	repCorrect, err := backup.VerifyBackup(outPath, passphrase)
	if err != nil {
		t.Fatalf("verify correct error: %v", err)
	}
	if !repCorrect.Valid {
		t.Fatalf("expected valid backup verification, got errors: %v", repCorrect.Errors)
	}
	if repCorrect.Manifest.TotalFiles < 3 {
		t.Errorf("expected at least 3 files, got %d", repCorrect.Manifest.TotalFiles)
	}

	// 4. Restore to isolated target directory
	tempDstDir, err := os.MkdirTemp("", "openmail-backup-dst-*")
	if err != nil {
		t.Fatalf("temp dst dir error: %v", err)
	}
	defer os.RemoveAll(tempDstDir)

	restoreRes, err := backup.RestoreBackup(ctx, outPath, passphrase, tempDstDir)
	if err != nil {
		t.Fatalf("restore failed: %v", err)
	}
	if restoreRes.FilesRestored < 3 {
		t.Errorf("expected at least 3 restored files, got %d", restoreRes.FilesRestored)
	}

	// Check restored contents
	restoredMsg, err := os.ReadFile(filepath.Join(tempDstDir, "maildir", "msg1.eml"))
	if err != nil || string(restoredMsg) != "From: alice@test.com\n\nSecret Email" {
		t.Errorf("restored maildir content mismatch: %s (%v)", string(restoredMsg), err)
	}
	restoredKey, err := os.ReadFile(filepath.Join(tempDstDir, "dkim", "mailopen.private"))
	if err != nil || string(restoredKey) != "-----BEGIN PRIVATE KEY-----\nMOCK_KEY\n-----END PRIVATE KEY-----" {
		t.Errorf("restored dkim key mismatch: %s (%v)", string(restoredKey), err)
	}
}
