package tests

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

	"github.com/azdharsyahputra/openmail/internal/database"
	"github.com/azdharsyahputra/openmail/internal/dkim"
	"github.com/azdharsyahputra/openmail/internal/domain"
	"github.com/azdharsyahputra/openmail/internal/mailbox"
	"github.com/azdharsyahputra/openmail/internal/provisioning"
	"github.com/google/uuid"
)


func TestIntegration_DKIM(t *testing.T) {
	// 1. Check live submission port :587
	conn587, err := net.DialTimeout("tcp", "127.0.0.1:587", 500*time.Millisecond)
	if err != nil {
		t.Skip("Submission port :587 not reachable, skipping live DKIM integration tests")
		return
	}
	_ = conn587.Close()

	insecureTLS := &tls.Config{
		InsecureSkipVerify: true,
	}

	t.Run("Keystore Permissions: Private Key 0600, Directory 0750", func(t *testing.T) {
		tempDir, err := os.MkdirTemp("", "openmail-dkim-perm-*")
		if err != nil {
			t.Fatalf("temp dir error: %v", err)
		}
		defer os.RemoveAll(tempDir)

		keystore := dkim.NewFilesystemKeystore(tempDir)
		pair, err := dkim.GenerateRSAKeyPair(2048)
		if err != nil {
			t.Fatalf("failed to generate key: %v", err)
		}

		keyPath, err := keystore.StorePrivateKey(t.Context(), "example.com", "mailopen2026", pair.PrivateKeyPEM)
		if err != nil {
			t.Fatalf("store private key error: %v", err)
		}

		info, err := os.Stat(keyPath)
		if err != nil {
			t.Fatalf("key stat error: %v", err)
		}
		if perm := info.Mode().Perm(); perm != 0600 {
			t.Errorf("expected 0600 key permission, got %04o", perm)
		}

		dirInfo, err := os.Stat(filepath.Dir(keyPath))
		if err != nil {
			t.Fatalf("dir stat error: %v", err)
		}
		if dirPerm := dirInfo.Mode().Perm(); dirPerm != 0750 {
			t.Errorf("expected 0750 directory permission, got %04o", dirPerm)
		}
	})

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		dbURL = "postgres://mailopen:mailopen@localhost:5433/mailopen?sslmode=disable"
	}
	db, err := database.NewPostgresDB(dbURL)
	if err == nil {
		defer db.Close()
		domRepo := domain.NewPostgresRepository(db)
		mbRepo := mailbox.NewPostgresRepository(db)
		prov, _ := provisioning.NewFilesystemProvisioner(os.TempDir(), 5000, 5000)
		mbSvc := mailbox.NewService(mbRepo, domRepo, prov)
		ctx := context.Background()
		_ = domRepo.Create(ctx, &domain.Domain{ID: uuid.New(), Name: "example.com", Status: "active"})
		_, _ = mbSvc.Create(ctx, "ajar@example.com", "SecurePass123", 1073741824)

		_, _, _ = mbSvc.Provision(ctx, "ajar@example.com")
		_, _ = mbSvc.Create(ctx, "bob@example.com", "SecurePass123", 1073741824)
		_, _, _ = mbSvc.Provision(ctx, "bob@example.com")
	}

	t.Run("Outbound DKIM Signing: :587 Submission -> OpenDKIM Milter -> DKIM-Signature", func(t *testing.T) {

		c, err := smtp.Dial("127.0.0.1:587")
		if err != nil {
			t.Fatalf("failed to connect to :587: %v", err)
		}
		defer c.Close()

		if err := c.StartTLS(insecureTLS); err != nil {
			t.Fatalf("STARTTLS failed: %v", err)
		}

		auth := &plainAuthNoTLS{username: "ajar@example.com", password: "SecurePass123"}
		if err := c.Auth(auth); err != nil {
			t.Fatalf("AUTH failed: %v", err)
		}

		if err := c.Mail("ajar@example.com"); err != nil {
			t.Fatalf("MAIL FROM failed: %v", err)
		}
		if err := c.Rcpt("bob@example.com"); err != nil {
			t.Fatalf("RCPT TO failed: %v", err)
		}

		w, err := c.Data()
		if err != nil {
			t.Fatalf("DATA failed: %v", err)
		}

		msgID := fmt.Sprintf("<dkim-test-%d@example.com>", time.Now().UnixNano())
		msg := fmt.Sprintf("From: ajar@example.com\r\nTo: bob@example.com\r\nSubject: DKIM Integration Test\r\nMessage-ID: %s\r\nDate: %s\r\n\r\nTesting DKIM Milter Signing\r\n",
			msgID,
			time.Now().Format(time.RFC1123Z),
		)

		if _, err := w.Write([]byte(msg)); err != nil {
			t.Fatalf("write payload failed: %v", err)
		}
		if err := w.Close(); err != nil {
			t.Fatalf("close DATA failed: %v", err)
		}
		_ = c.Quit()

		// Wait briefly for delivery
		time.Sleep(500 * time.Millisecond)

		// Verify delivered message has DKIM-Signature
		maildirNew := "./data/vmail/example.com/bob/Maildir/new"
		if _, err := os.Stat(maildirNew); err != nil {
			maildirNew = "../data/vmail/example.com/bob/Maildir/new"
		}

		entries, err := os.ReadDir(maildirNew)
		if err != nil || len(entries) == 0 {
			t.Fatalf("no delivered messages found in Bob maildir: %v", err)
		}

		var latestContent string
		var latestMod time.Time
		for _, e := range entries {
			p := filepath.Join(maildirNew, e.Name())
			info, err := e.Info()
			if err == nil && info.ModTime().After(latestMod) {
				latestMod = info.ModTime()
				bytes, err := os.ReadFile(p)
				if err == nil {
					latestContent = string(bytes)
				}
			}
		}

		if !strings.Contains(latestContent, "DKIM-Signature:") {
			t.Errorf("delivered message does not contain DKIM-Signature header:\n%s", latestContent)
		}
		if !strings.Contains(latestContent, "d=example.com") {
			t.Errorf("DKIM-Signature missing d=example.com domain tag")
		}
		if !strings.Contains(latestContent, "s=mailopen2026") {
			t.Errorf("DKIM-Signature missing s=mailopen2026 selector tag")
		}
		if !strings.Contains(latestContent, "a=rsa-sha256") {
			t.Errorf("DKIM-Signature missing a=rsa-sha256 algorithm tag")
		}
	})

	t.Run("Sender Anti-Spoofing with DKIM: Spoofed sender rejected before signing", func(t *testing.T) {
		c, err := smtp.Dial("127.0.0.1:587")
		if err != nil {
			t.Fatalf("failed to connect to :587: %v", err)
		}
		defer c.Close()

		_ = c.StartTLS(insecureTLS)
		auth := &plainAuthNoTLS{username: "ajar@example.com", password: "SecurePass123"}
		if err := c.Auth(auth); err != nil {
			t.Fatalf("AUTH failed: %v", err)
		}

		// Spoofed sender (ajar trying to send as ceo@bank.com)
		_ = c.Mail("ceo@bank.com")
		err = c.Rcpt("external@recipient.com")
		if err == nil {
			t.Errorf("expected spoofed sender to be rejected with 553 on RCPT")
		}
	})

}
