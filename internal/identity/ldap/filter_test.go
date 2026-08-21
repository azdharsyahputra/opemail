package ldap_test

import (
	"strings"
	"testing"

	"github.com/azdharsyahputra/openmail/internal/identity/ldap"
)

func TestLDAP_FilterEscapingAndSecurity(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Normal alphanumeric input",
			input:    "ajar",
			expected: "ajar",
		},
		{
			name:     "Asterisk wildcard escaping",
			input:    "ajar*",
			expected: `ajar\2a`,
		},
		{
			name:     "Parentheses injection escaping",
			input:    "ajar)(uid=*",
			expected: `ajar\29\28uid=\2a`,
		},
		{
			name:     "Backslash escaping",
			input:    `domain\user`,
			expected: `domain\5cuser`,
		},
		{
			name:     "Null byte escaping",
			input:    "user\x00admin",
			expected: `user\00admin`,
		},
		{
			name:     "Complex LDAP injection payload",
			input:    `*)(uid=*))(|(uid=*`,
			expected: `\2a\29\28uid=\2a\29\29\28|\28uid=\2a`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			escaped := ldap.EscapeFilter(tc.input)
			if escaped != tc.expected {
				t.Errorf("expected %q, got %q", tc.expected, escaped)
			}
		})
	}
}

func TestLDAP_BuildUserFilter(t *testing.T) {
	t.Run("Safe filter generation", func(t *testing.T) {
		template := "(|(mail={username})(uid={username}))"
		user := "ajar@example.com"
		filter, err := ldap.BuildUserFilter(template, user)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		expected := "(|(mail=ajar@example.com)(uid=ajar@example.com))"
		if filter != expected {
			t.Errorf("expected %q, got %q", expected, filter)
		}
	})

	t.Run("LDAP injection payload neutralised in filter", func(t *testing.T) {
		template := "(mail={username})"
		injectionPayload := "admin*)(uid=*"
		filter, err := ldap.BuildUserFilter(template, injectionPayload)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// Injection must be escaped as literal assertion value
		if strings.Contains(filter, "admin*)(uid=*") {
			t.Errorf("raw injection substring found in generated filter: %s", filter)
		}
		if !strings.Contains(filter, `admin\2a\29\28uid=\2a`) {
			t.Errorf("expected escaped payload in filter, got: %s", filter)
		}
	})
}

func TestLDAP_BuildGroupFilter(t *testing.T) {
	template := "(|(member={dn})(uniqueMember={dn}))"
	userDN := "uid=ajar,ou=people,dc=example,dc=com"
	username := "ajar"

	filter, err := ldap.BuildGroupFilter(template, userDN, username)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(filter, "uid=ajar,ou=people,dc=example,dc=com") {
		t.Errorf("expected user DN in group filter, got: %s", filter)
	}
}
