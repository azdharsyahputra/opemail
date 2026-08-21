package dns

import (
	"errors"
	"fmt"
	"strings"
)

var (
	ErrInvalidSPFSyntax = errors.New("invalid spf syntax")
)

// ValidateSPFSyntax validates SPF record syntax according to RFC 7208.
func ValidateSPFSyntax(spf string) error {
	spf = strings.TrimSpace(spf)
	spf = strings.Trim(spf, "\"")

	if !strings.HasPrefix(spf, "v=spf1") {
		return fmt.Errorf("%w: record must start with 'v=spf1'", ErrInvalidSPFSyntax)
	}

	terms := strings.Fields(spf)
	if len(terms) < 2 {
		return fmt.Errorf("%w: record contains no mechanisms or modifiers", ErrInvalidSPFSyntax)
	}

	for _, term := range terms[1:] {
		// Valid mechanisms can start with qualifiers: +, -, ~, ?
		cleaned := strings.TrimLeft(term, "+-~?")
		if cleaned == "" {
			return fmt.Errorf("%w: invalid qualifier-only token '%s'", ErrInvalidSPFSyntax, term)
		}

		lower := strings.ToLower(cleaned)
		if lower == "all" || lower == "mx" || lower == "a" || lower == "ptr" {
			continue
		}

		if strings.HasPrefix(lower, "ip4:") || strings.HasPrefix(lower, "ip6:") ||
			strings.HasPrefix(lower, "include:") || strings.HasPrefix(lower, "redirect=") ||
			strings.HasPrefix(lower, "exists:") || strings.HasPrefix(lower, "exp=") {
			continue
		}

		return fmt.Errorf("%w: unrecognized SPF mechanism '%s'", ErrInvalidSPFSyntax, term)
	}

	return nil
}

// GenerateDefaultSPF returns the recommended initial SPF policy for a domain.
func GenerateDefaultSPF() string {
	return "v=spf1 mx ~all"
}
