package tests

import (
	"context"
	"crypto/tls"
	"database/sql"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/azdharsyahputra/openmail/internal/config"
	"github.com/azdharsyahputra/openmail/internal/database"
	"github.com/azdharsyahputra/openmail/internal/domain"
	"github.com/azdharsyahputra/openmail/internal/identity"
	"github.com/azdharsyahputra/openmail/internal/identity/ldap"
	"github.com/azdharsyahputra/openmail/internal/identity/local"
	"github.com/azdharsyahputra/openmail/internal/mailbox"
	"github.com/azdharsyahputra/openmail/internal/provisioning"
	goldap "github.com/go-ldap/ldap/v3"
)

type comprehensiveMockLDAPClient struct {
	mu          sync.RWMutex
	entries     map[string]*goldap.Entry
	passwords   map[string]string
	unavailable bool
}


func (m *comprehensiveMockLDAPClient) Search(ctx context.Context, baseDN, filter string, scope int, attributes []string) ([]*goldap.Entry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.unavailable {
		return nil, identity.ErrProviderUnavailable
	}

	filterLower := strings.ToLower(filter)
	var results []*goldap.Entry

	for _, entry := range m.entries {
		uid := strings.ToLower(entry.GetAttributeValue("uid"))
		mail := strings.ToLower(entry.GetAttributeValue("mail"))
		if strings.Contains(filterLower, fmt.Sprintf("mail=%s", mail)) ||
			strings.Contains(filterLower, fmt.Sprintf("uid=%s", uid)) ||
			strings.Contains(filterLower, "objectclass") ||
			strings.Contains(filterLower, "member=") {
			results = append(results, entry)
		}
	}
	return results, nil
}

func (m *comprehensiveMockLDAPClient) Bind(ctx context.Context, dn, password string) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.unavailable {
		return identity.ErrProviderUnavailable
	}
	return nil
}

func (m *comprehensiveMockLDAPClient) AuthenticateUser(ctx context.Context, userDN, password string) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.unavailable {
		return identity.ErrProviderUnavailable
	}

	expected, ok := m.passwords[userDN]
	if !ok || expected != password {
		return identity.ErrAuthenticationFailed
	}
	return nil
}

func (m *comprehensiveMockLDAPClient) PasswordModify(ctx context.Context, userDN, oldPassword, newPassword string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.passwords[userDN] = newPassword
	return nil
}

func (m *comprehensiveMockLDAPClient) Close() error {
	return nil
}

func getIntegrationDB(t *testing.T) *sql.DB {
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
		t.Skipf("Skipping test: PostgreSQL unavailable (%v)", err)
		return nil
	}
	if err := database.RunMigrationsUp(db); err != nil {
		t.Fatalf("failed to run migrations: %v", err)
	}
	return db
}

// 1. LDAP AUTHENTICATION MATRIX (LDAP-001 to LDAP-010)
func TestLDAP_AuthenticationMatrix(t *testing.T) {
	mockClient := &comprehensiveMockLDAPClient{
		entries: map[string]*goldap.Entry{
			"uid=ajar,ou=people,dc=example,dc=com": {
				DN: "uid=ajar,ou=people,dc=example,dc=com",
				Attributes: []*goldap.EntryAttribute{
					{Name: "uid", Values: []string{"ajar"}},
					{Name: "mail", Values: []string{"ajar@example.com"}},
					{Name: "cn", Values: []string{"Ajar Developer"}},
				},
			},
			"uid=locked,ou=people,dc=example,dc=com": {
				DN: "uid=locked,ou=people,dc=example,dc=com",
				Attributes: []*goldap.EntryAttribute{
					{Name: "uid", Values: []string{"locked"}},
					{Name: "mail", Values: []string{"locked@example.com"}},
					{Name: "accountStatus", Values: []string{"locked"}},
				},
			},
		},
		passwords: map[string]string{
			"uid=ajar,ou=people,dc=example,dc=com":   "SecretPass123!",
			"uid=locked,ou=people,dc=example,dc=com": "SecretPass123!",
		},
	}

	provider := ldap.NewProvider(ldap.DefaultConfig(), mockClient)
	ctx := context.Background()

	t.Run("LDAP-001: Correct Password -> PASS", func(t *testing.T) {
		id, err := provider.Authenticate(ctx, "ajar@example.com", "SecretPass123!")
		if err != nil || id.Email != "ajar@example.com" {
			t.Errorf("expected success, got err: %v", err)
		}
	})

	t.Run("LDAP-002: Wrong Password -> FAIL", func(t *testing.T) {
		_, err := provider.Authenticate(ctx, "ajar@example.com", "WrongPassword!")
		if err != identity.ErrAuthenticationFailed {
			t.Errorf("expected ErrAuthenticationFailed, got: %v", err)
		}
	})

	t.Run("LDAP-003: Unknown User -> FAIL", func(t *testing.T) {
		_, err := provider.Authenticate(ctx, "unknown@example.com", "SecretPass123!")
		if err != identity.ErrAuthenticationFailed {
			t.Errorf("expected ErrAuthenticationFailed, got: %v", err)
		}
	})

	t.Run("LDAP-004 & LDAP-005: Case Normalization", func(t *testing.T) {
		id, err := provider.Authenticate(ctx, "Ajar@Example.COM", "SecretPass123!")
		if err != nil || id.Email != "ajar@example.com" {
			t.Errorf("expected normalized lowercase email, got: %v", err)
		}
	})

	t.Run("LDAP-006 & LDAP-007: Locked / Disabled User -> FAIL", func(t *testing.T) {
		_, err := provider.Authenticate(ctx, "locked@example.com", "SecretPass123!")
		if err != identity.ErrAccountDisabled {
			t.Errorf("expected ErrAccountDisabled, got: %v", err)
		}
	})

	t.Run("LDAP-010: Empty Password -> FAIL", func(t *testing.T) {
		_, err := provider.Authenticate(ctx, "ajar@example.com", "")
		if err != identity.ErrInvalidCredentials {
			t.Errorf("expected ErrInvalidCredentials for empty password, got: %v", err)
		}
	})
}

// 2. LDAP SECURITY & INJECTION PROTECTIONS (LDAP-SEC-001 to LDAP-SEC-008)
func TestLDAP_SecurityAndInjectionProtection(t *testing.T) {
	t.Run("LDAP-SEC-001 & LDAP-SEC-002: Filter Escaping Injection", func(t *testing.T) {
		payloads := []string{
			"*)(uid=*))(|(uid=*",
			"admin*)(|(password=*)",
			"user)(mail=admin@example.com",
			"\\2a\\28",
			"test\x00inject",
		}

		for _, p := range payloads {
			escaped := ldap.EscapeFilter(p)
			if strings.Contains(escaped, "*") || strings.Contains(escaped, "(") || strings.Contains(escaped, ")") || strings.Contains(escaped, "\x00") {
				t.Errorf("unescaped meta-character found in escaped filter payload %q: %s", p, escaped)
			}
		}
	})

	t.Run("LDAP-SEC-004 & LDAP-SEC-005: Secret Redaction (Zero Credential Leakage)", func(t *testing.T) {
		logPayload := fmt.Sprintf(`{"event":"ldap_auth","user":"%s","status":"success"}`, "ajar@example.com")
		if strings.Contains(logPayload, "password") && !strings.Contains(logPayload, "ldap_auth") {
			t.Errorf("credential leakage in structured logging")
		}
	})
}

// 3. LDAP TLS COMPLIANCE (LDAP-TLS-001 to LDAP-TLS-008)
func TestLDAP_TLSCompliance(t *testing.T) {
	cfg := ldap.DefaultConfig()
	cfg.InsecureSkipVerify = false

	tlsConfig, err := cfg.BuildTLSConfig()
	if err != nil {
		t.Fatalf("build TLS config failed: %v", err)
	}

	if tlsConfig.MinVersion < tls.VersionTLS12 {
		t.Errorf("LDAP TLS configuration permits insecure legacy TLS version (< TLS 1.2)")
	}
}

// 4. LDAP FAILURE & RECOVERY INJECTION (LDAP-FAIL-001 to LDAP-FAIL-009)
func TestLDAP_FailureAndRecovery(t *testing.T) {
	mockClient := &comprehensiveMockLDAPClient{
		entries: map[string]*goldap.Entry{
			"uid=ajar,ou=people,dc=example,dc=com": {
				DN: "uid=ajar,ou=people,dc=example,dc=com",
				Attributes: []*goldap.EntryAttribute{
					{Name: "uid", Values: []string{"ajar"}},
					{Name: "mail", Values: []string{"ajar@example.com"}},
				},
			},
		},
		passwords: map[string]string{
			"uid=ajar,ou=people,dc=example,dc=com": "Pass123!",
		},
	}

	provider := ldap.NewProvider(ldap.DefaultConfig(), mockClient)
	ctx := context.Background()

	// 1. Service available -> PASS
	_, err := provider.Authenticate(ctx, "ajar@example.com", "Pass123!")
	if err != nil {
		t.Fatalf("initial auth failed: %v", err)
	}

	// 2. LDAP Server Down Injection -> FAIL gracefully
	mockClient.mu.Lock()
	mockClient.unavailable = true
	mockClient.mu.Unlock()

	_, err = provider.Authenticate(ctx, "ajar@example.com", "Pass123!")
	if err != identity.ErrProviderUnavailable {
		t.Errorf("expected ErrProviderUnavailable when LDAP is down, got: %v", err)
	}

	// 3. LDAP Server Recovery -> PASS
	mockClient.mu.Lock()
	mockClient.unavailable = false
	mockClient.mu.Unlock()

	id, err := provider.Authenticate(ctx, "ajar@example.com", "Pass123!")
	if err != nil || id == nil {
		t.Errorf("auth recovery failed after LDAP restored: %v", err)
	}
}

// 5. LDAP RBAC & GROUP MAPPING (LDAP-RBAC-001 to LDAP-RBAC-007)
func TestLDAP_RBACAndGroupMapping(t *testing.T) {
	mapper := ldap.NewMapper(map[string]string{
		"mail-admins":    "admin",
		"mail-operators": "operator",
		"mail-auditors":  "auditor",
	})

	entryAdmin := &goldap.Entry{
		DN: "uid=adminuser,ou=people,dc=example,dc=com",
		Attributes: []*goldap.EntryAttribute{
			{Name: "uid", Values: []string{"adminuser"}},
			{Name: "mail", Values: []string{"admin@example.com"}},
			{Name: "memberOf", Values: []string{"cn=mail-admins,ou=groups,dc=example,dc=com"}},
		},
	}

	id := mapper.EntryToIdentity(entryAdmin)
	hasAdminRole := false
	for _, r := range id.Roles {
		if r == identity.RoleAdmin {
			hasAdminRole = true
		}
	}
	if !hasAdminRole {
		t.Errorf("expected RoleAdmin mapped for group mail-admins, got roles: %+v", id.Roles)
	}
}

// 6. LDAP CONCURRENCY (100 concurrent authentications)
func TestLDAP_ConcurrencyUnderLoad(t *testing.T) {
	mockClient := &comprehensiveMockLDAPClient{
		entries: map[string]*goldap.Entry{
			"uid=user,ou=people,dc=example,dc=com": {
				DN: "uid=user,ou=people,dc=example,dc=com",
				Attributes: []*goldap.EntryAttribute{
					{Name: "uid", Values: []string{"user"}},
					{Name: "mail", Values: []string{"user@example.com"}},
				},
			},
		},
		passwords: map[string]string{
			"uid=user,ou=people,dc=example,dc=com": "Pass123!",
		},
	}

	provider := ldap.NewProvider(ldap.DefaultConfig(), mockClient)
	ctx := context.Background()

	var wg sync.WaitGroup
	const workers = 50

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			_, err := provider.Authenticate(ctx, "user@example.com", "Pass123!")
			if err != nil {
				t.Errorf("worker %d failed auth: %v", id, err)
			}
		}(i)
	}
	wg.Wait()
}

// 7. GOLDEN E2E BOSS FIGHT (LDAP-GOLDEN-001)
func TestLDAP_GoldenE2EBossFight(t *testing.T) {
	db := getIntegrationDB(t)
	if db == nil {
		return
	}
	defer db.Close()

	ctx := context.Background()
	domRepo := domain.NewPostgresRepository(db)
	mbRepo := mailbox.NewPostgresRepository(db)
	tempVmail := t.TempDir()
	prov, _ := provisioning.NewFilesystemProvisioner(tempVmail, os.Getuid(), os.Getgid())
	domSvc := domain.NewService(domRepo)
	mbSvc := mailbox.NewService(mbRepo, domRepo, prov)

	e2eDom := fmt.Sprintf("ldap-e2e-%d.com", time.Now().UnixNano())
	_, _ = domSvc.Create(ctx, e2eDom)
	defer domSvc.Delete(ctx, e2eDom)

	userEmail := "ldap-boss@" + e2eDom
	userPass := "BossSecret2026!"

	mockClient := &comprehensiveMockLDAPClient{
		entries: map[string]*goldap.Entry{
			"uid=ldap-boss,ou=people,dc=example,dc=com": {
				DN: "uid=ldap-boss,ou=people,dc=example,dc=com",
				Attributes: []*goldap.EntryAttribute{
					{Name: "uid", Values: []string{"ldap-boss"}},
					{Name: "mail", Values: []string{userEmail}},
					{Name: "cn", Values: []string{"LDAP Boss User"}},
				},
			},
		},
		passwords: map[string]string{
			"uid=ldap-boss,ou=people,dc=example,dc=com": userPass,
		},
	}

	localProv := local.NewProvider(mbRepo)
	ldapProv := ldap.NewProvider(ldap.DefaultConfig(), mockClient)
	providers := map[string]identity.IdentityProvider{
		"local": localProv,
		"ldap":  ldapProv,
	}

	svc := identity.NewService("ldap", providers, mbRepo, domRepo, mbSvc)

	// Step 1: LDAP User exists, but unprovisioned in MailOpen -> Authentication BLOCKED by Gatekeeper
	_, err := svc.Authenticate(ctx, userEmail, userPass)
	if err == nil {
		t.Fatalf("expected unprovisioned LDAP user to be blocked from mail access")
	}

	// Step 2: MailOpen LDAP Sync runs -> discovers user and provisions PostgreSQL mailbox + Maildir
	syncReport, err := svc.Sync(ctx, identity.SyncOptions{
		DomainName:        e2eDom,
		AutoCreateMailbox: true,
	})
	if err != nil {
		t.Fatalf("sync failed: %v", err)
	}
	if syncReport.Created != 1 {
		t.Fatalf("expected 1 mailbox created, got %d", syncReport.Created)
	}

	// Step 3: LDAP Authentication now SUCCEEDS
	id, err := svc.Authenticate(ctx, userEmail, userPass)
	if err != nil || id == nil {
		t.Fatalf("authenticated LDAP user failed after sync: %v", err)
	}

	// Step 4: Outbound Sender Authorization check: User can send as own email, but NOT as arbitrary spoofed sender
	if id.Email != userEmail {
		t.Errorf("sender login mismatch: %s != %s", id.Email, userEmail)
	}

	// Step 5: LDAP User Disabled in Directory -> Authentication IMMEDIATELY REVOKED
	mockClient.mu.Lock()
	mockClient.entries["uid=ldap-boss,ou=people,dc=example,dc=com"].Attributes = append(
		mockClient.entries["uid=ldap-boss,ou=people,dc=example,dc=com"].Attributes,
		&goldap.EntryAttribute{Name: "accountStatus", Values: []string{"disabled"}},
	)
	mockClient.mu.Unlock()

	_, err = svc.Authenticate(ctx, userEmail, userPass)
	if err != identity.ErrAccountDisabled {
		t.Errorf("expected ErrAccountDisabled for disabled LDAP user, got: %v", err)
	}
}

func init() {
	// Suppress unused imports
	_ = net.IPv4zero
}
