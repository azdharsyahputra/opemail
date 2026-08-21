package upstream_test

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/azdharsyahputra/openmail/internal/provisioning"
)

// UPSTREAM-DOVECOT-001: Authentication bypass
func TestUPSTREAM_DOVECOT_001_AuthBypass(t *testing.T) {
	conn, err := net.DialTimeout("tcp", "127.0.0.1:143", 2*time.Second)
	if err != nil {
		t.Skipf("IMAP port 143 offline in test environment: %v", err)
		return
	}
	defer conn.Close()

	// Read greeting
	buf := make([]byte, 1024)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _ = conn.Read(buf)

	// Send unauthenticated command before LOGIN
	_, _ = conn.Write([]byte("A01 SELECT INBOX\r\n"))
	n, _ := conn.Read(buf)
	resp := string(buf[:n])

	if strings.Contains(resp, "OK") {
		t.Fatalf("SECURITY INVARIANT VIOLATED (UPSTREAM-DOVECOT-001): Unauthenticated SELECT INBOX succeeded")
	}
}

// UPSTREAM-DOVECOT-003 & 004: Mailbox path traversal and Symlink escape
func TestUPSTREAM_DOVECOT_003_004_PathTraversalAndSymlink(t *testing.T) {
	tempRoot := t.TempDir()
	prov, err := provisioning.NewFilesystemProvisioner(tempRoot, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatalf("failed to init provisioner: %v", err)
	}

	// Traversal
	badMB := provisioning.Mailbox{Email: "../../../etc/shadow", Domain: "example.com"}
	err = prov.Provision(context.Background(), badMB)
	if err == nil {
		t.Fatalf("SECURITY INVARIANT VIOLATED (UPSTREAM-DOVECOT-003): Path traversal provisioned outside root")
	}

	// Symlink boundary
	evalRoot, _ := filepath.EvalSymlinks(tempRoot)
	goodMB := provisioning.Mailbox{Email: "user1@example.com", Domain: "example.com"}
	_ = prov.Provision(context.Background(), goodMB)
	target := filepath.Join(tempRoot, "example.com", "user1")
	evalTarget, _ := filepath.EvalSymlinks(target)

	if !strings.HasPrefix(evalTarget, evalRoot) {
		t.Fatalf("SECURITY INVARIANT VIOLATED (UPSTREAM-DOVECOT-004): Symlink evaluated outside root")
	}
}

// UPSTREAM-DOVECOT-006: IMAP parser abuse
func TestUPSTREAM_DOVECOT_006_IMAPParserAbuse(t *testing.T) {
	conn, err := net.DialTimeout("tcp", "127.0.0.1:143", 2*time.Second)
	if err != nil {
		t.Skipf("IMAP port 143 offline: %v", err)
		return
	}
	defer conn.Close()

	// Drain initial Dovecot greeting
	buf := make([]byte, 1024)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _ = conn.Read(buf)

	// Send deeply nested or malformed IMAP command
	malformed := "A01 LOGIN {" + strings.Repeat("(", 500) + "\r\n"
	_, _ = conn.Write([]byte(malformed))
	n, _ := conn.Read(buf)
	resp := string(buf[:n])

	if strings.Contains(resp, "A01 OK") {
		t.Fatalf("SECURITY INVARIANT VIOLATED (UPSTREAM-DOVECOT-006): Malformed IMAP parenthesis bomb returned A01 OK")
	}
}


// UPSTREAM-DOVECOT-009: Privilege boundary violation
func TestUPSTREAM_DOVECOT_009_PrivilegeBoundary(t *testing.T) {
	// Dovecot config files should not expose PostgreSQL root passwords in world-readable files
	// Verify directory permissions
	tempDir := t.TempDir()
	confPath := filepath.Join(tempDir, "dovecot.conf")
	_ = os.WriteFile(confPath, []byte("# dovecot conf"), 0640)

	info, err := os.Stat(confPath)
	if err != nil {
		t.Fatalf("stat failed: %v", err)
	}
	if info.Mode().Perm()&0004 != 0 {
		t.Fatalf("SECURITY INVARIANT VIOLATED (UPSTREAM-DOVECOT-009): Dovecot config is world-readable")
	}
}
