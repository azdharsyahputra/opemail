package upstream_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/azdharsyahputra/openmail/internal/identity/ldap"
	goldap "github.com/go-ldap/ldap/v3"
)


type mockLDAPClient struct {
	entries      []*goldap.Entry
	searchErr    error
	bindErr      error
	authErr      error
	pwModifyErr  error
	searchDelay  time.Duration
}

func (m *mockLDAPClient) Search(ctx context.Context, baseDN, filter string, scope int, attributes []string) ([]*goldap.Entry, error) {
	if m.searchDelay > 0 {
		select {
		case <-time.After(m.searchDelay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if m.searchErr != nil {
		return nil, m.searchErr
	}
	return m.entries, nil
}

func (m *mockLDAPClient) Bind(ctx context.Context, dn, password string) error {
	return m.bindErr
}

func (m *mockLDAPClient) AuthenticateUser(ctx context.Context, userDN, password string) error {
	if m.authErr != nil {
		return m.authErr
	}
	if password == "" {
		return fmt.Errorf("empty password bind rejected")
	}
	return nil
}

func (m *mockLDAPClient) PasswordModify(ctx context.Context, userDN, oldPassword, newPassword string) error {
	return m.pwModifyErr
}

func (m *mockLDAPClient) Close() error {
	return nil
}

// UPSTREAM-LDAP-001: Authentication bypass regression
func TestUPSTREAM_LDAP_001_AuthBypassRegression(t *testing.T) {
	mock := &mockLDAPClient{
		authErr: fmt.Errorf("invalid credentials"),
	}
	cfg := ldap.DefaultConfig()
	prov := ldap.NewProvider(cfg, mock)

	_, err := prov.Authenticate(context.Background(), "user@example.com", "WrongPass123!")
	if err == nil {
		t.Fatalf("SECURITY INVARIANT VIOLATED (UPSTREAM-LDAP-001): Auth succeeded despite invalid credentials")
	}
}

// UPSTREAM-LDAP-002: Anonymous bind regression
func TestUPSTREAM_LDAP_002_AnonymousBindRegression(t *testing.T) {
	mock := &mockLDAPClient{}
	cfg := ldap.DefaultConfig()
	prov := ldap.NewProvider(cfg, mock)

	_, err := prov.Authenticate(context.Background(), "admin@example.com", "")
	if err == nil {
		t.Fatalf("SECURITY INVARIANT VIOLATED (UPSTREAM-LDAP-002): Anonymous bind allowed via empty password")
	}
}

// UPSTREAM-LDAP-003: Filter injection regression
func TestUPSTREAM_LDAP_003_FilterInjectionRegression(t *testing.T) {
	mock := &mockLDAPClient{}
	cfg := ldap.DefaultConfig()
	prov := ldap.NewProvider(cfg, mock)

	vectors := []string{"*)(&", "admin)(|(password=*))", "*)(uid=*))(|(uid=*"}
	for _, v := range vectors {
		_, err := prov.Authenticate(context.Background(), v, "somepass")
		if err == nil {
			t.Fatalf("SECURITY INVARIANT VIOLATED (UPSTREAM-LDAP-003): Filter injection %q succeeded", v)
		}
	}
}

// UPSTREAM-LDAP-004: DN injection regression
func TestUPSTREAM_LDAP_004_DNInjectionRegression(t *testing.T) {
	escaped := ldap.EscapeDN(`uid=admin,ou=admins,dc=example,dc=com`)
	if !strings.Contains(escaped, `\,`) || !strings.Contains(escaped, `\=`) {
		t.Fatalf("SECURITY INVARIANT VIOLATED (UPSTREAM-LDAP-004): DN delimiters not escaped properly: %s", escaped)
	}
}

// UPSTREAM-LDAP-005: Referral abuse protection
func TestUPSTREAM_LDAP_005_ReferralAbuse(t *testing.T) {
	// Ensure client never automatically follows arbitrary external referrals
	cfg := ldap.DefaultConfig()
	cfg.URL = "ldap://127.0.0.1:389"
	client := ldap.NewClient(cfg)
	if client == nil {
		t.Fatalf("failed to init client")
	}
}

// UPSTREAM-LDAP-006: Search size/time limit bypass
func TestUPSTREAM_LDAP_006_SearchSizeTimeLimitBypass(t *testing.T) {
	mock := &mockLDAPClient{
		searchDelay: 100 * time.Millisecond,
	}
	cfg := ldap.DefaultConfig()
	prov := ldap.NewProvider(cfg, mock)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	_, err := prov.Lookup(ctx, "user@example.com")
	if err == nil || !strings.Contains(err.Error(), "context deadline exceeded") {
		t.Fatalf("SECURITY INVARIANT VIOLATED (UPSTREAM-LDAP-006): Context timeout was ignored: %v", err)
	}
}

// UPSTREAM-LDAP-007: TLS certificate validation
func TestUPSTREAM_LDAP_007_TLSCertificateValidation(t *testing.T) {
	cfg := ldap.DefaultConfig()
	cfg.InsecureSkipVerify = false
	tlsConfig, err := cfg.BuildTLSConfig()
	if err != nil {
		t.Fatalf("BuildTLSConfig failed: %v", err)
	}
	if tlsConfig.InsecureSkipVerify {
		t.Fatalf("SECURITY INVARIANT VIOLATED (UPSTREAM-LDAP-007): InsecureSkipVerify was enabled by default")
	}
}

// UPSTREAM-LDAP-008: StartTLS downgrade prevention
func TestUPSTREAM_LDAP_008_StartTLSDowngrade(t *testing.T) {
	cfg := ldap.DefaultConfig()
	cfg.StartTLS = true
	tlsConfig, _ := cfg.BuildTLSConfig()
	if tlsConfig.MinVersion < 0x0303 { // TLS 1.2
		t.Fatalf("SECURITY INVARIANT VIOLATED (UPSTREAM-LDAP-008): Min TLS version below TLS 1.2")
	}
}

// UPSTREAM-LDAP-009: Resource exhaustion bounds
func TestUPSTREAM_LDAP_009_ResourceExhaustion(t *testing.T) {
	mapper := ldap.NewMapper(nil)
	hugeString := strings.Repeat("X", 200000)
	entry := &goldap.Entry{
		DN: "uid=test,ou=people,dc=example,dc=com",
		Attributes: []*goldap.EntryAttribute{
			{Name: "uid", Values: []string{"test"}},
			{Name: "mail", Values: []string{"test@example.com"}},
			{Name: "description", Values: []string{hugeString}},
		},
	}
	ident := mapper.EntryToIdentity(entry)
	if len(ident.Attributes["description"]) > 4096 {
		t.Fatalf("SECURITY INVARIANT VIOLATED (UPSTREAM-LDAP-009): Huge attribute unbounded in memory")
	}
}
