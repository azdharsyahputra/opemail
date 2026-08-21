package quota_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/azdharsyahputra/openmail/internal/quota"
)

func TestQuotaThresholds(t *testing.T) {
	quotaBytes := int64(1000)

	t.Run("Usage < 80% -> Status OK", func(t *testing.T) {
		status, pct, isExceeded := quota.ComputeStatus(700, quotaBytes)
		if status != quota.StatusOK || pct != 70.0 || isExceeded {
			t.Errorf("expected OK, got status: %s, pct: %.1f, isExceeded: %t", status, pct, isExceeded)
		}
	})

	t.Run("Usage 80-89% -> Status WARNING", func(t *testing.T) {
		status, pct, isExceeded := quota.ComputeStatus(850, quotaBytes)
		if status != quota.StatusWarning || pct != 85.0 || isExceeded {
			t.Errorf("expected WARNING, got status: %s, pct: %.1f, isExceeded: %t", status, pct, isExceeded)
		}
	})

	t.Run("Usage 90-99% -> Status CRITICAL", func(t *testing.T) {
		status, pct, isExceeded := quota.ComputeStatus(950, quotaBytes)
		if status != quota.StatusCritical || pct != 95.0 || isExceeded {
			t.Errorf("expected CRITICAL, got status: %s, pct: %.1f, isExceeded: %t", status, pct, isExceeded)
		}
	})

	t.Run("Usage >= 100% -> Status FULL", func(t *testing.T) {
		status, pct, isExceeded := quota.ComputeStatus(1000, quotaBytes)
		if status != quota.StatusFull || pct != 100.0 || !isExceeded {
			t.Errorf("expected FULL, got status: %s, pct: %.1f, isExceeded: %t", status, pct, isExceeded)
		}
	})
}

func TestCalculateMaildirUsage(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "openmail-maildir-quota-*")
	if err != nil {
		t.Fatalf("temp dir error: %v", err)
	}
	defer os.RemoveAll(tempDir)

	curDir := filepath.Join(tempDir, "cur")
	newDir := filepath.Join(tempDir, "new")
	_ = os.MkdirAll(curDir, 0750)
	_ = os.MkdirAll(newDir, 0750)

	msg1 := []byte("From: user1@example.com\nSubject: Test 1\n\nHello 1234567890")
	msg2 := []byte("From: user2@example.com\nSubject: Test 2\n\nWorld 1234567890")

	_ = os.WriteFile(filepath.Join(curDir, "msg1.eml"), msg1, 0640)
	_ = os.WriteFile(filepath.Join(newDir, "msg2.eml"), msg2, 0640)
	// Control file that should be ignored
	_ = os.WriteFile(filepath.Join(tempDir, "dovecot.index"), []byte("index metadata"), 0640)

	scan, err := quota.CalculateMaildirUsage(tempDir)
	if err != nil {
		t.Fatalf("calculate usage error: %v", err)
	}

	expectedBytes := int64(len(msg1) + len(msg2))
	if scan.TotalBytes != expectedBytes {
		t.Errorf("expected total bytes %d, got %d", expectedBytes, scan.TotalBytes)
	}
	if scan.MessageCount != 2 {
		t.Errorf("expected 2 messages, got %d", scan.MessageCount)
	}
}
