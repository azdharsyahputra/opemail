package security_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/azdharsyahputra/openmail/internal/domain"
	"github.com/azdharsyahputra/openmail/internal/identity"
	"github.com/azdharsyahputra/openmail/internal/identity/ldap"
	"github.com/azdharsyahputra/openmail/internal/identity/local"
	"github.com/azdharsyahputra/openmail/internal/mailbox"
	"github.com/azdharsyahputra/openmail/internal/provisioning"
)

// TestDependency_FailClosedAndSecretSanitization verifies fail-closed provider semantics
// and secret protection across error propagation
func TestDependency_FailClosedAndSecretSanitization(t *testing.T) {
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

	testDom := fmt.Sprintf("depsec-%d.com", time.Now().UnixNano())
	_ = domRepo.Create(ctx, &domain.Domain{Name: testDom, Status: "active"})
	defer domRepo.Delete(ctx, testDom)

	userEmail := "ldapuser@" + testDom
	mb, _ := mbSvc.Create(ctx, userEmail, "SecretLocalPass999!", 1073741824)
	_ = mbRepo.UpdateIdentityProvider(ctx, mb.ID, "ldap")
	_, _, _ = mbSvc.Provision(ctx, userEmail)

	// Failing LDAP client
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

	_, err := identSvc.Authenticate(ctx, userEmail, "SecretLocalPass999!")
	if err == nil {
		t.Fatalf("SECURITY INVARIANT VIOLATED: Fail-closed violated on dead LDAP provider")
	}

	// Verify error string does NOT leak passwords or sensitive tokens
	errStr := err.Error()
	if strings.Contains(errStr, "SecretLocalPass999!") {
		t.Fatalf("SECURITY INVARIANT VIOLATED: Plaintext password leaked in error message: %s", errStr)
	}
}
