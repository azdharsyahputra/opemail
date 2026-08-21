package dkim

import (
	"regexp"
	"strings"
)

var selectorRegex = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)

// ValidateSelector checks if the selector conforms to standard DKIM DNS label specs and prevents path traversal.
func ValidateSelector(selector string) error {
	selector = strings.TrimSpace(strings.ToLower(selector))
	if selector == "" {
		return ErrInvalidSelector
	}

	if strings.Contains(selector, "/") || strings.Contains(selector, "\\") || strings.Contains(selector, "..") {
		return ErrInvalidSelector
	}

	if !selectorRegex.MatchString(selector) {
		return ErrInvalidSelector
	}

	return nil
}

// BuildDNSName returns the full DKIM DNS TXT record hostname. Example: "mailopen2026._domainkey.example.com"
func BuildDNSName(domain, selector string) string {
	return strings.ToLower(strings.TrimSpace(selector)) + "._domainkey." + strings.ToLower(strings.TrimSpace(domain))
}

// BuildDNSTXTValue formats the public key value for the DNS TXT record. Example: "v=DKIM1; k=rsa; p=MIIB..."
func BuildDNSTXTValue(publicKeyDNS string) string {
	return "v=DKIM1; k=rsa; p=" + publicKeyDNS
}
