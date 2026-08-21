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
	goldap "github.com/go-ldap/ldap/v3"
)

type mockExtendedLDAPClient struct {
	entries   map[string]*goldap.Entry
	passwords map[string]string
	searchErr error
	bindErr   error
}

func (m *mockExtendedLDAPClient) Search(ctx context.Context, baseDN, filter string, scope int, attributes []string) ([]*goldap.Entry, error) {
	if m.searchErr != nil {
		return nil, m.searchErr
	}
	var results []*goldap.Entry
	for _, entry := range m.entries {
		results = append(results, entry)
	}
	return results, nil
}

func (m *mockExtendedLDAPClient) Bind(ctx context.Context, dn, password string) error {
	return m.bindErr
}

func (m *mockExtendedLDAPClient) AuthenticateUser(ctx context.Context, userDN, password string) error {
	if m.bindErr != nil {
		return m.bindErr
	}
	if p, ok := m.passwords[userDN]; ok && p == password {
		return nil
	}
	return fmt.Errorf("invalid password")
}

func (m *mockExtendedLDAPClient) PasswordModify(ctx context.Context, userDN, oldPassword, newPassword string) error {
	m.passwords[userDN] = newPassword
	return nil
}

func (m *mockExtendedLDAPClient) Close() error {
	return nil
}

// LDAP-SEC-017 & LDAP-SEC-018: Search Scope Escape & Base DN Injection Protection
func TestGate_LDAP_SEC_017_018_ScopeEscapeAndBaseDNContainment(t *testing.T) {
	cfg := ldap.DefaultConfig()
	cfg.UserBaseDN = "ou=people,dc=example,dc=com"

	// Mock entry returned from outside the configured UserBaseDN
	mockClient := &mockExtendedLDAPClient{
		entries: map[string]*goldap.Entry{
			"uid=admin,ou=sensitive_admins,dc=other,dc=com": {
				DN: "uid=admin,ou=sensitive_admins,dc=other,dc=com",
				Attributes: []*goldap.EntryAttribute{
					{Name: "uid", Values: []string{"admin"}},
					{Name: "mail", Values: []string{"admin@example.com"}},
				},
			},
		},
		passwords: map[string]string{
			"uid=admin,ou=sensitive_admins,dc=other,dc=com": "AdminPass!",
		},
	}

	prov := ldap.NewProvider(cfg, mockClient)

	// Attempt auth with entry located outside UserBaseDN
	_, err := prov.Authenticate(context.Background(), "admin@example.com", "AdminPass!")
	if err == nil || !strings.Contains(err.Error(), "security violation") {
		t.Fatalf("expected security violation for DN outside UserBaseDN, got: %v", err)
	}

	// Attempt lookup with entry located outside UserBaseDN
	_, err = prov.Lookup(context.Background(), "admin@example.com")
	if err == nil || !strings.Contains(err.Error(), "security violation") {
		t.Fatalf("expected security violation for Lookup DN outside UserBaseDN, got: %v", err)
	}
}

// LDAP-SEC-020: LDAP URL & SSRF Validation
func TestGate_LDAP_SEC_020_URLValidation(t *testing.T) {
	invalidURLs := []string{
		"http://evil.com/ldap",
		"file:///etc/passwd",
		"gopher://localhost:11211",
		"javascript:alert(1)",
	}

	for _, u := range invalidURLs {
		cfg := ldap.DefaultConfig()
		cfg.URL = u
		client := ldap.NewClient(cfg)
		err := client.Bind(context.Background(), "cn=admin", "secret")
		if err == nil {
			t.Errorf("expected error for invalid/dangerous LDAP URL scheme %q, got nil", u)
		}
	}
}

// LDAP-SEC-023: Malicious LDAP Server Response Handling
func TestGate_LDAP_SEC_023_MaliciousServerResponse(t *testing.T) {
	mapper := ldap.NewMapper(nil)

	t.Run("Invalid UTF-8 sequences sanitized without panic", func(t *testing.T) {
		entry := &goldap.Entry{
			DN: "uid=badutf8,ou=people,dc=example,dc=com",
			Attributes: []*goldap.EntryAttribute{
				{Name: "uid", Values: []string{"user\xff\xfe"}},
				{Name: "mail", Values: []string{"bad\xff\xfe@example.com"}},
				{Name: "displayName", Values: []string{"Name\xff\xfe"}},
			},
		}
		ident := mapper.EntryToIdentity(entry)
		if ident == nil {
			t.Fatalf("expected identity returned, got nil")
		}
		if strings.Contains(ident.Email, "\xff") {
			t.Errorf("invalid UTF-8 byte preserved in email: %s", ident.Email)
		}
	})

	t.Run("Oversized attribute bounded to maxAttrBytes", func(t *testing.T) {
		hugeString := strings.Repeat("A", 100000)
		entry := &goldap.Entry{
			DN: "uid=huge,ou=people,dc=example,dc=com",
			Attributes: []*goldap.EntryAttribute{
				{Name: "uid", Values: []string{"huge"}},
				{Name: "mail", Values: []string{"huge@example.com"}},
				{Name: "displayName", Values: []string{hugeString}},
			},
		}
		ident := mapper.EntryToIdentity(entry)
		if len(ident.DisplayName) > 4096 {
			t.Errorf("displayName was not bounded, size: %d", len(ident.DisplayName))
		}
	})

	t.Run("Duplicate memberOf groups deduplicated cleanly", func(t *testing.T) {
		entry := &goldap.Entry{
			DN: "uid=dup,ou=people,dc=example,dc=com",
			Attributes: []*goldap.EntryAttribute{
				{Name: "uid", Values: []string{"dup"}},
				{Name: "mail", Values: []string{"dup@example.com"}},
				{Name: "memberOf", Values: []string{
					"cn=mail-admins,ou=groups,dc=example,dc=com",
					"cn=mail-admins,ou=groups,dc=example,dc=com",
					"cn=mail-admins,ou=groups,dc=example,dc=com",
				}},
			},
		}
		ident := mapper.EntryToIdentity(entry)
		if len(ident.Roles) != 1 || ident.Roles[0] != identity.RoleAdmin {
			t.Errorf("roles not cleanly deduplicated: %v", ident.Roles)
		}
	})
}

// LDAP-SEC-024: Fail-Closed Provider Switching (Strictly No Implicit Fallback)
func TestGate_LDAP_SEC_024_FailClosedProviderSwitching(t *testing.T) {
	db := setupSecurityTestDB(t)
	if db == nil {
		return
	}
	defer db.Close()

	ctx := context.Background()
	domRepo := domain.NewPostgresRepository(db)
	mbRepo := mailbox.NewPostgresRepository(db)
	tempDir := t.TempDir()
	prov, _ := provisioning.NewFilesystemProvisioner(tempDir, 5000, 5000)
	mbSvc := mailbox.NewService(mbRepo, domRepo, prov)

	testDom := fmt.Sprintf("failclose-%d.com", time.Now().UnixNano())
	_ = domRepo.Create(ctx, &domain.Domain{Name: testDom, Status: "active"})
	defer domRepo.Delete(ctx, testDom)


	ldapUserEmail := "ldapuser@" + testDom
	mb, _ := mbSvc.Create(ctx, ldapUserEmail, "LocalPassword123!", 1073741824)
	_ = mbRepo.UpdateIdentityProvider(ctx, mb.ID, "ldap")
	_, _, _ = mbSvc.Provision(ctx, ldapUserEmail)

	// Mock FAILING LDAP client (LDAP server is completely down)
	failingClient := &mockExtendedLDAPClient{
		searchErr: fmt.Errorf("connection refused: ldap service is down"),
		bindErr:   fmt.Errorf("connection refused"),
	}
	ldapProv := ldap.NewProvider(ldap.DefaultConfig(), failingClient)
	localProv := local.NewProvider(mbRepo)

	providers := map[string]identity.IdentityProvider{
		"local": localProv,
		"ldap":  ldapProv,
	}
	identSvc := identity.NewService("ldap", providers, mbRepo, domRepo, mbSvc)

	// Attempt login with the valid local password while LDAP is down
	// Expected: FAIL-CLOSED! Authentication MUST FAIL because identity_provider is LDAP.
	_, err := identSvc.Authenticate(ctx, ldapUserEmail, "LocalPassword123!")
	if err == nil {
		t.Fatalf("SECURITY VIOLATION: implicit fallback allowed local password authentication for LDAP user when LDAP was down!")
	}
}

// Directory Sync: Mailbox Hijacking & Takeover Protection Invariants
func TestGate_LDAP_DirectorySync_AntiHijackingAndTakeover(t *testing.T) {
	db := setupSecurityTestDB(t)
	if db == nil {
		return
	}
	defer db.Close()

	ctx := context.Background()
	domRepo := domain.NewPostgresRepository(db)
	mbRepo := mailbox.NewPostgresRepository(db)
	tempDir := t.TempDir()
	prov, _ := provisioning.NewFilesystemProvisioner(tempDir, 5000, 5000)
	mbSvc := mailbox.NewService(mbRepo, domRepo, prov)

	testDom := fmt.Sprintf("synchijack-%d.com", time.Now().UnixNano())
	_ = domRepo.Create(ctx, &domain.Domain{Name: testDom, Status: "active"})
	defer domRepo.Delete(ctx, testDom)


	// Pre-existing LOCAL administrator account
	localAdminEmail := "admin@" + testDom
	_, _ = mbSvc.Create(ctx, localAdminEmail, "LocalAdminPass123!", 1073741824)
	_, _, _ = mbSvc.Provision(ctx, localAdminEmail)

	// Mock LDAP returning:
	// 1. Attacker attempting to claim "admin@<testDom>"
	// 2. Duplicate email entries claiming "duplicate@<testDom>"
	// 3. Unicode / invalid email format "attacker@\u0430pp\u04cf\u0435.com"
	// 4. Valid new user "validuser@<testDom>"
	mockClient := &mockExtendedLDAPClient{
		entries: map[string]*goldap.Entry{
			"uid=attacker,ou=people,dc=example,dc=com": {
				DN: "uid=attacker,ou=people,dc=example,dc=com",
				Attributes: []*goldap.EntryAttribute{
					{Name: "uid", Values: []string{"attacker"}},
					{Name: "mail", Values: []string{localAdminEmail}}, // Attempt to hijack local admin!
				},
			},
			"uid=dup1,ou=people,dc=example,dc=com": {
				DN: "uid=dup1,ou=people,dc=example,dc=com",
				Attributes: []*goldap.EntryAttribute{
					{Name: "uid", Values: []string{"dup1"}},
					{Name: "mail", Values: []string{"shared@" + testDom}},
				},
			},
			"uid=dup2,ou=people,dc=example,dc=com": {
				DN: "uid=dup2,ou=people,dc=example,dc=com",
				Attributes: []*goldap.EntryAttribute{
					{Name: "uid", Values: []string{"dup2"}},
					{Name: "mail", Values: []string{"shared@" + testDom}}, // Duplicate collision!
				},
			},
			"uid=unicode,ou=people,dc=example,dc=com": {
				DN: "uid=unicode,ou=people,dc=example,dc=com",
				Attributes: []*goldap.EntryAttribute{
					{Name: "uid", Values: []string{"unicode"}},
					{Name: "mail", Values: []string{"user@домен.рф"}}, // Non-ASCII homograph
				},
			},
			"uid=validuser,ou=people,dc=example,dc=com": {
				DN: "uid=validuser,ou=people,dc=example,dc=com",
				Attributes: []*goldap.EntryAttribute{
					{Name: "uid", Values: []string{"validuser"}},
					{Name: "mail", Values: []string{"validuser@" + testDom}},
				},
			},
		},
	}

	ldapProv := ldap.NewProvider(ldap.DefaultConfig(), mockClient)
	providers := map[string]identity.IdentityProvider{
		"local": local.NewProvider(mbRepo),
		"ldap":  ldapProv,
	}
	identSvc := identity.NewService("ldap", providers, mbRepo, domRepo, mbSvc)

	// Execute Directory Sync with AutoCreate enabled
	report, err := identSvc.Sync(ctx, identity.SyncOptions{
		DomainName:        testDom,
		AutoCreateMailbox: true,
		DefaultQuotaBytes: 1073741824,
	})
	if err != nil {
		t.Fatalf("sync execution failed: %v", err)
	}

	// 1. Verify valid user was created
	if report.Created != 1 {
		t.Errorf("expected exactly 1 created mailbox (validuser), got: %d", report.Created)
	}

	// 2. Verify local admin was NOT hijacked or overwritten
	adminMB, err := mbRepo.GetByEmail(ctx, localAdminEmail)
	if err != nil || adminMB.IdentityProvider != "local" {
		t.Fatalf("SECURITY VIOLATION: local admin mailbox was hijacked by LDAP sync! Provider: %s", adminMB.IdentityProvider)
	}

	// 3. Verify duplicate email entries were rejected with collision errors
	foundCollision := false
	for _, e := range report.Errors {
		if strings.Contains(e, "collision") {
			foundCollision = true
			break
		}
	}
	if !foundCollision {
		t.Errorf("expected collision error for duplicate LDAP emails in directory report, got: %v", report.Errors)
	}

	// 4. Verify unicode / homograph email was rejected
	foundUnicodeErr := false
	for _, e := range report.Errors {
		if strings.Contains(e, "invalid email format") || strings.Contains(e, "unicode") {
			foundUnicodeErr = true
			break
		}
	}
	if !foundUnicodeErr {
		t.Errorf("expected invalid format error for unicode email, got: %v", report.Errors)
	}
}
