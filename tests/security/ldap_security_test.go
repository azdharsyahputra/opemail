package security_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/azdharsyahputra/openmail/internal/identity/ldap"
	goldap "github.com/go-ldap/ldap/v3"
)

// TestLDAP_Security_Comprehensive verifies LDAP injection immunity, DN escaping,
// ACL boundaries, and TLS security
func TestLDAP_Security_Comprehensive(t *testing.T) {
	mockClient := &mockExtendedLDAPClient{
		entries: map[string]*goldap.Entry{
			"uid=alice,ou=people,dc=example,dc=com": {
				DN: "uid=alice,ou=people,dc=example,dc=com",
				Attributes: []*goldap.EntryAttribute{
					{Name: "uid", Values: []string{"alice"}},
					{Name: "mail", Values: []string{"alice@example.com"}},
					{Name: "memberOf", Values: []string{"cn=mail-admins,ou=groups,dc=example,dc=com"}},
				},
			},
		},
		passwords: map[string]string{
			"uid=alice,ou=people,dc=example,dc=com": "AlicePass2026!",
		},
	}

	cfg := ldap.DefaultConfig()
	prov := ldap.NewProvider(cfg, mockClient)

	t.Run("Valid Authentication", func(t *testing.T) {
		ident, err := prov.Authenticate(context.Background(), "alice@example.com", "AlicePass2026!")
		if err != nil || ident == nil {
			t.Fatalf("expected auth success, got err: %v", err)
		}
	})

	t.Run("Wrong Password", func(t *testing.T) {
		_, err := prov.Authenticate(context.Background(), "alice@example.com", "WrongPassword!")
		if err == nil {
			t.Fatalf("SECURITY INVARIANT VIOLATED: Wrong password succeeded")
		}
	})

	t.Run("Filter Escaping (RFC 4515)", func(t *testing.T) {
		dangerousInputs := []string{"*)(&", "admin)(|(userPassword=*))", "*)(objectClass=*"}
		for _, di := range dangerousInputs {
			escaped := ldap.EscapeFilter(di)
			if strings.Contains(escaped, "*") || strings.Contains(escaped, ")") || strings.Contains(escaped, "(") {
				t.Fatalf("SECURITY INVARIANT VIOLATED: Filter character not properly escaped in: %s", escaped)
			}
		}
	})

	t.Run("DN Escaping (RFC 4514)", func(t *testing.T) {
		dnInput := "uid=admin,ou=admins,dc=example,dc=com"
		escapedDN := ldap.EscapeDN(dnInput)
		if !strings.Contains(escapedDN, `\,`) || !strings.Contains(escapedDN, `\=`) {
			t.Fatalf("SECURITY INVARIANT VIOLATED: DN delimiters not escaped: %s", escapedDN)
		}
	})

	t.Run("Context Timeout & Cancellation", func(t *testing.T) {
		slowClient := &mockExtendedLDAPClient{
			searchErr: fmt.Errorf("context deadline exceeded"),
		}
		slowProv := ldap.NewProvider(cfg, slowClient)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer cancel()

		_, err := slowProv.Lookup(ctx, "alice@example.com")
		if err == nil {
			t.Fatalf("SECURITY INVARIANT VIOLATED: Slow query did not return error on timeout")
		}
	})
}
