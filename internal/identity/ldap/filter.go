package ldap

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/azdharsyahputra/openmail/internal/identity"
)

// EscapeFilter escapes special characters in an LDAP search filter assertion value (RFC 4515).
func EscapeFilter(filter string) string {
	var buf bytes.Buffer
	for i := 0; i < len(filter); i++ {
		c := filter[i]
		switch c {
		case '\\':
			buf.WriteString(`\5c`)
		case '*':
			buf.WriteString(`\2a`)
		case '(':
			buf.WriteString(`\28`)
		case ')':
			buf.WriteString(`\29`)
		case 0:
			buf.WriteString(`\00`)
		default:
			buf.WriteByte(c)
		}
	}
	return buf.String()
}

// EscapeDN escapes characters with special meaning in LDAP Distinguished Names (RFC 4514).
func EscapeDN(dn string) string {
	if dn == "" {
		return ""
	}
	var buf bytes.Buffer
	n := len(dn)
	for i := 0; i < n; i++ {
		c := dn[i]
		if i == 0 && (c == ' ' || c == '#') {
			buf.WriteByte('\\')
			buf.WriteByte(c)
			continue
		}
		if i == n-1 && c == ' ' {
			buf.WriteByte('\\')
			buf.WriteByte(c)
			continue
		}
		switch c {
		case '\\', ',', '+', '"', '<', '>', ';', '=':
			buf.WriteByte('\\')
			buf.WriteByte(c)
		case 0:
			buf.WriteString(`\00`)
		default:
			buf.WriteByte(c)
		}
	}
	return buf.String()
}


// BuildUserFilter builds a safe LDAP search filter replacing {username} with escaped input.
func BuildUserFilter(template, username string) (string, error) {
	if template == "" {
		template = "(|(mail={username})(uid={username}))"
	}
	if !strings.Contains(template, "{username}") {
		return "", fmt.Errorf("invalid user filter template: missing {username} placeholder")
	}

	escapedUser := EscapeFilter(username)
	filter := strings.ReplaceAll(template, "{username}", escapedUser)

	// Validate basic parentheses balance
	openCount := strings.Count(filter, "(")
	closeCount := strings.Count(filter, ")")
	if openCount != closeCount || openCount == 0 {
		return "", identity.ErrLDAPInjectionDetected
	}

	return filter, nil
}

// BuildGroupFilter builds a safe group search filter replacing {dn} and {username}.
func BuildGroupFilter(template, userDN, username string) (string, error) {
	if template == "" {
		template = "(|(member={dn})(uniqueMember={dn}))"
	}

	escapedDN := EscapeFilter(userDN)
	escapedUser := EscapeFilter(username)

	filter := strings.ReplaceAll(template, "{dn}", escapedDN)
	filter = strings.ReplaceAll(filter, "{username}", escapedUser)

	return filter, nil
}
