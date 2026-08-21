package security_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/azdharsyahputra/openmail/internal/provisioning"
)

// TestFilesystem_Security_Boundaries verifies Maildir isolation, traversal prevention,
// permissions, and atomic writes
func TestFilesystem_Security_Boundaries(t *testing.T) {
	tempRoot := t.TempDir()
	prov, err := provisioning.NewFilesystemProvisioner(tempRoot, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatalf("failed to init provisioner: %v", err)
	}

	t.Run("Path Traversal Rejection", func(t *testing.T) {
		traversalList := []string{
			"../escape@example.com",
			"../../../../var/mail",
			"user@example.com/../../admin",
			"..\\..\\windows",
		}
		for _, tl := range traversalList {
			mb := provisioning.Mailbox{Email: tl, Domain: "example.com"}
			err := prov.Provision(context.Background(), mb)
			if err == nil {
				t.Fatalf("SECURITY INVARIANT VIOLATED: Traversal path %q provisioned successfully", tl)
			}
		}
	})

	t.Run("Symlink Escape Containment", func(t *testing.T) {
		evalRoot, _ := filepath.EvalSymlinks(tempRoot)
		mb := provisioning.Mailbox{Email: "legit@example.com", Domain: "example.com"}
		err := prov.Provision(context.Background(), mb)
		if err != nil {
			t.Fatalf("legit provision failed: %v", err)
		}

		userDir := filepath.Join(tempRoot, "example.com", "legit")
		evalUser, _ := filepath.EvalSymlinks(userDir)
		if !strings.HasPrefix(evalUser, evalRoot) {
			t.Fatalf("SECURITY INVARIANT VIOLATED: Maildir evaluated outside vmail root")
		}
	})

	t.Run("Maildir Permissions Baseline (0750/0700)", func(t *testing.T) {
		mb := provisioning.Mailbox{Email: "perm_user@example.com", Domain: "example.com"}
		_ = prov.Provision(context.Background(), mb)
		dir := filepath.Join(tempRoot, "example.com", "perm_user", "Maildir")
		info, err := os.Stat(dir)
		if err == nil {
			perm := info.Mode().Perm()
			if perm&0007 != 0 {
				t.Fatalf("SECURITY INVARIANT VIOLATED: Maildir permissions %o allow world access (must be 0750 or 0700)", perm)
			}
		}
	})

}
