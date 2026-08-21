package ldap_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/azdharsyahputra/openmail/internal/identity"
	"github.com/azdharsyahputra/openmail/internal/identity/ldap"
	goldap "github.com/go-ldap/ldap/v3"
)

type mockLDAPClient struct {
	entries      map[string]*goldap.Entry
	passwords    map[string]string
	bindError    error
	searchError  error
	authenticateFunc func(ctx context.Context, userDN, password string) error
}

func (m *mockLDAPClient) Search(ctx context.Context, baseDN, filter string, scope int, attributes []string) ([]*goldap.Entry, error) {
	if m.searchError != nil {
		return nil, m.searchError
	}

	var results []*goldap.Entry
	filterLower := strings.ToLower(filter)
	for _, entry := range m.entries {
		// Mock simple filter matching
		uid := strings.ToLower(entry.GetAttributeValue("uid"))
		mail := strings.ToLower(entry.GetAttributeValue("mail"))
		if strings.Contains(filterLower, fmt.Sprintf("mail=%s", mail)) || strings.Contains(filterLower, fmt.Sprintf("uid=%s", uid)) || strings.Contains(filterLower, "objectclass") {
			results = append(results, entry)
		}
	}
	return results, nil

}

func (m *mockLDAPClient) Bind(ctx context.Context, dn, password string) error {
	if m.bindError != nil {
		return m.bindError
	}
	return nil
}

func (m *mockLDAPClient) AuthenticateUser(ctx context.Context, userDN, password string) error {
	if m.authenticateFunc != nil {
		return m.authenticateFunc(ctx, userDN, password)
	}
	expectedPass, ok := m.passwords[userDN]
	if !ok || expectedPass != password {
		return identity.ErrAuthenticationFailed
	}
	return nil
}

func (m *mockLDAPClient) PasswordModify(ctx context.Context, userDN, oldPassword, newPassword string) error {
	m.passwords[userDN] = newPassword
	return nil
}

func (m *mockLDAPClient) Close() error {
	return nil
}

func TestLDAPProvider_Authentication(t *testing.T) {
	cfg := ldap.DefaultConfig()
	mockClient := &mockLDAPClient{
		entries: map[string]*goldap.Entry{
			"uid=ajar,ou=people,dc=example,dc=com": {
				DN: "uid=ajar,ou=people,dc=example,dc=com",
				Attributes: []*goldap.EntryAttribute{
					{Name: "uid", Values: []string{"ajar"}},
					{Name: "mail", Values: []string{"ajar@example.com"}},
					{Name: "cn", Values: []string{"Ajar Dev"}},
				},
			},
			"uid=disabled,ou=people,dc=example,dc=com": {
				DN: "uid=disabled,ou=people,dc=example,dc=com",
				Attributes: []*goldap.EntryAttribute{
					{Name: "uid", Values: []string{"disabled"}},
					{Name: "mail", Values: []string{"disabled@example.com"}},
					{Name: "accountStatus", Values: []string{"disabled"}},
				},
			},
		},
		passwords: map[string]string{
			"uid=ajar,ou=people,dc=example,dc=com":     "SecretPass123!",
			"uid=disabled,ou=people,dc=example,dc=com": "SecretPass123!",
		},
	}

	provider := ldap.NewProvider(cfg, mockClient)
	ctx := context.Background()

	t.Run("LDAP-001: Correct password -> PASS", func(t *testing.T) {
		id, err := provider.Authenticate(ctx, "ajar@example.com", "SecretPass123!")
		if err != nil {
			t.Fatalf("expected successful auth, got error: %v", err)
		}
		if id.Email != "ajar@example.com" {
			t.Errorf("expected email ajar@example.com, got %s", id.Email)
		}
	})

	t.Run("LDAP-002: Wrong password -> FAIL", func(t *testing.T) {
		_, err := provider.Authenticate(ctx, "ajar@example.com", "WrongPassword!")
		if err == nil {
			t.Errorf("expected authentication error on wrong password")
		}
	})

	t.Run("LDAP-003: Unknown user -> FAIL", func(t *testing.T) {
		_, err := provider.Authenticate(ctx, "nonexistent@example.com", "SecretPass123!")
		if err == nil {
			t.Errorf("expected error for nonexistent user")
		}
	})

	t.Run("LDAP-004: Uppercase email normalization", func(t *testing.T) {
		id, err := provider.Authenticate(ctx, "AJAR@EXAMPLE.COM", "SecretPass123!")
		if err != nil {
			t.Fatalf("expected uppercase email to pass auth, got: %v", err)
		}
		if id.Email != "ajar@example.com" {
			t.Errorf("expected lowercase email, got: %s", id.Email)
		}
	})

	t.Run("LDAP-006: Disabled LDAP user -> ErrAccountDisabled", func(t *testing.T) {
		_, err := provider.Authenticate(ctx, "disabled@example.com", "SecretPass123!")
		if err != identity.ErrAccountDisabled {
			t.Errorf("expected ErrAccountDisabled, got: %v", err)
		}
	})

	t.Run("LDAP-008: Password change through provider", func(t *testing.T) {
		err := provider.SetPassword(ctx, "ajar@example.com", "NewRotatedPass456!")
		if err != nil {
			t.Fatalf("password change failed: %v", err)
		}

		// Verify new password authenticates
		_, err = provider.Authenticate(ctx, "ajar@example.com", "NewRotatedPass456!")
		if err != nil {
			t.Errorf("failed to authenticate with updated password: %v", err)
		}
	})
}
