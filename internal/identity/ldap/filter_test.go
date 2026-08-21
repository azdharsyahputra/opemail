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

// Full verification of PayloadsAllTheThings LDAP Injection Corpus:
// Reference: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/LDAP%20Injection/README.md
func TestLDAP_PayloadsAllTheThings_InjectionCorpus(t *testing.T) {
	payloads := []struct {
		name    string
		payload string
	}{
		{"Universal Wildcard", "*"},
		{"AND Injection", "*)(&"},
		{"Null Byte Injection", "*))%00"},
		{"Admin AND True Injection", "admin)(&)"},
		{"Password Wildcard Injection", "admin)(|(password=*))"},
		{"Negation Injection", "admin)(!(&(1=0)))"},
		{"Nested UID Injection", "*)(uid=*))(|(uid=*"},
		{"User Mail Injection", "user)(|(mail=*))"},
		{"Special Character Mash", "*()|&'"},
		{"Prefix Wildcard", "admin*"},
		{"Path Traversal Style", "*/*"},
		{"ObjectClass Injection", "*)(objectClass=*"},
		{"AD User Injection", "admin)(objectClass=user"},
		{"SQL-like Injection", "1' or '1' = '1"},
		{"XPath-like Injection", "x' or name()='username' or 'x'='y"},
		{"UserPassword Blind Extraction", "admin)(|(userPassword=*))"},
		{"Double Backslash Bomb", `\\`},
		{"Embedded NUL Byte", "user\x00admin"},
		{"Unbalanced Open Paren Injection", "*)(&(1=1"},
		{"Objectclass Blind Query", "admin*)(|(objectclass=*))"},
		{"CN Extraction", ")(|(cn=*))"},
		{"UID Extraction", ")(|(uid=*))"},
		{"Mail Extraction", ")(|(mail=*))"},
		{"Description Extraction", "admin)(|(description=*))"},
	}

	template := "(&(objectClass=inetOrgPerson)(|(mail={username})(uid={username})))"

	for _, p := range payloads {
		t.Run("Payload: "+p.name, func(t *testing.T) {
			filter, err := ldap.BuildUserFilter(template, p.payload)
			if err != nil {
				// Rejected before filter construction is secure
				return
			}

			// In all cases where a filter is generated, raw unescaped injection tokens must NEVER alter AST
			if strings.Contains(p.payload, "*") && strings.Contains(filter, p.payload) {
				t.Errorf("raw wildcard found in filter for payload %q: %s", p.payload, filter)
			}
			if strings.Contains(p.payload, ")(") && strings.Contains(filter, p.payload) {
				t.Errorf("raw AST delimiter ')(' found unescaped for payload %q: %s", p.payload, filter)
			}

			// Ensure open and close parenthesis count remains exactly equal to template structure (5 open '(' and 5 close ')')
			// because all injected '(' and ')' MUST be escaped as '\28' and '\29'
			openCount := strings.Count(filter, "(")
			closeCount := strings.Count(filter, ")")
			if openCount != 5 || closeCount != 5 {
				t.Errorf("filter parenthesis structure altered by payload %q: %s (opens: %d, closes: %d)", p.payload, filter, openCount, closeCount)
			}

		})
	}
}

func TestLDAP_EscapeDN_RFC4514(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected string
	}{
		{"Empty DN", "", ""},
		{"Simple DN", "uid=ajar,ou=people,dc=example,dc=com", `uid\=ajar\,ou\=people\,dc\=example\,dc\=com`},
		{"Leading Space", " ajar", `\ ajar`},
		{"Trailing Space", "ajar ", `ajar\ `},
		{"Leading Hash", "#admin", `\#admin`},
		{"Quotes and Plus", `cn="John+Doe"`, `cn\=\"John\+Doe\"`},
		{"Semicolon and Angles", `cn=<John;Doe>`, `cn\=\<John\;Doe\>`},
		{"NUL byte in DN", "uid=admin\x00injection", `uid\=admin\00injection`},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := ldap.EscapeDN(tc.input)
			if got != tc.expected {
				t.Errorf("expected %q, got %q", tc.expected, got)
			}
		})
	}
}

