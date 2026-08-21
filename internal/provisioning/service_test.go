package provisioning_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/azdharsyahputra/openmail/internal/provisioning"
)

func TestFilesystemProvisioner(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "openmail-vmail-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	prov, err := provisioning.NewFilesystemProvisioner(tempDir, 0, 0)
	if err != nil {
		t.Fatalf("failed to create provisioner: %v", err)
	}
	svc := provisioning.NewService(prov)
	ctx := context.Background()

	mb := provisioning.Mailbox{
		ID:         "mb-001",
		Email:      "ajar@example.com",
		Domain:     "example.com",
		QuotaBytes: 1073741824,
	}

	t.Run("Valid mailbox path calculation", func(t *testing.T) {
		path, err := prov.CalculatePath("ajar@example.com")
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		expected := filepath.Join(tempDir, "example.com", "ajar", "Maildir")
		if path != expected {
			t.Errorf("expected path %s, got %s", expected, path)
		}
	})

	t.Run("Invalid email rejected", func(t *testing.T) {
		invalidEmails := []string{"invalid", "@example.com", "user@", "", "user@@example.com"}
		for _, email := range invalidEmails {
			_, err := prov.CalculatePath(email)
			if err != provisioning.ErrInvalidMailbox {
				t.Errorf("expected ErrInvalidMailbox for %q, got %v", email, err)
			}
		}
	})

	t.Run("Path traversal rejected", func(t *testing.T) {
		traversalEmails := []string{
			"../../etc/passwd@example.com",
			"user@../../etc/passwd",
			"user/subfolder@example.com",
			"user\\subfolder@example.com",
		}
		for _, email := range traversalEmails {
			_, err := prov.CalculatePath(email)
			if err != provisioning.ErrPathTraversal && err != provisioning.ErrInvalidMailbox {
				t.Errorf("expected path traversal or invalid error for %q, got %v", email, err)
			}
		}
	})

	t.Run("Provision creates Maildir structure", func(t *testing.T) {
		err := svc.Provision(ctx, mb)
		if err != nil {
			t.Fatalf("expected no error provisioning mailbox, got %v", err)
		}

		maildirPath := filepath.Join(tempDir, "example.com", "ajar", "Maildir")
		subdirs := []string{"", "cur", "new", "tmp"}
		for _, sub := range subdirs {
			dirPath := filepath.Join(maildirPath, sub)
			info, err := os.Stat(dirPath)
			if err != nil || !info.IsDir() {
				t.Errorf("expected directory %s to exist, err=%v", dirPath, err)
			}
			if perm := info.Mode().Perm(); perm != 0750 {
				t.Errorf("expected permissions 0750 on %s, got %04o", dirPath, perm)
			}
		}
	})

	t.Run("Provision is idempotent", func(t *testing.T) {
		for i := 0; i < 3; i++ {
			err := svc.Provision(ctx, mb)
			if err != nil {
				t.Fatalf("expected idempotent provision on attempt %d, got %v", i+1, err)
			}
		}
	})

	t.Run("Inspect returns healthy report", func(t *testing.T) {
		report, err := svc.Inspect(ctx, mb)
		if err != nil {
			t.Fatalf("failed to inspect mailbox: %v", err)
		}
		if !report.Healthy {
			t.Errorf("expected report to be healthy, got %+v", report)
		}
		if !report.MaildirExists.Passed || !report.CurExists.Passed || !report.NewExists.Passed || !report.TmpExists.Passed {
			t.Errorf("expected all directory checks to pass, got %+v", report)
		}
	})

	t.Run("Deprovision removes Maildir", func(t *testing.T) {
		err := svc.Deprovision(ctx, mb)
		if err != nil {
			t.Fatalf("failed to deprovision mailbox: %v", err)
		}

		maildirPath := filepath.Join(tempDir, "example.com", "ajar", "Maildir")
		if _, err := os.Stat(maildirPath); !os.IsNotExist(err) {
			t.Errorf("expected Maildir %s to be removed", maildirPath)
		}

		// Deprovision should also be idempotent
		err = svc.Deprovision(ctx, mb)
		if err != nil {
			t.Errorf("expected idempotent deprovision, got %v", err)
		}
	})
}
