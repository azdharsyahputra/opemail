package inbound

import (
	"fmt"
	"strings"
)

// BuildAuthenticationResults formats an RFC 8601 compliant Authentication-Results header.
func BuildAuthenticationResults(eval *InboundEvaluation) string {
	authServID := eval.AuthServID
	if authServID == "" {
		authServID = "mail.example.com"
	}

	var parts []string
	parts = append(parts, authServID+";")

	// SPF entry
	spfDomain := eval.SPF.Domain
	if spfDomain == "" && eval.MailFrom != "" {
		partsM := strings.Split(eval.MailFrom, "@")
		if len(partsM) == 2 {
			spfDomain = partsM[1]
		}
	}
	parts = append(parts, fmt.Sprintf("    spf=%s (sender IP is %s) smtp.mailfrom=%s;",
		eval.SPF.Status,
		eval.ClientIP.String(),
		spfDomain,
	))

	// DKIM entry
	if eval.DKIM.Domain != "" {
		parts = append(parts, fmt.Sprintf("    dkim=%s header.d=%s header.s=%s;",
			eval.DKIM.Status,
			eval.DKIM.Domain,
			eval.DKIM.Selector,
		))
	} else {
		parts = append(parts, fmt.Sprintf("    dkim=%s (no signatures);", eval.DKIM.Status))
	}

	// DMARC entry
	headerFromDomain := eval.HeaderFrom
	if strings.Contains(headerFromDomain, "@") {
		partsF := strings.Split(headerFromDomain, "@")
		headerFromDomain = partsF[len(partsF)-1]
	}
	parts = append(parts, fmt.Sprintf("    dmarc=%s (p=%s) header.from=%s",
		eval.DMARC.Status,
		eval.DMARC.Policy,
		headerFromDomain,
	))

	return "Authentication-Results: " + strings.Join(parts, "\n")
}

// BuildReceivedSPF formats an RFC 7208 compliant Received-SPF header.
func BuildReceivedSPF(eval *InboundEvaluation) string {
	authServID := eval.AuthServID
	if authServID == "" {
		authServID = "mail.example.com"
	}

	spfDomain := eval.SPF.Domain
	if spfDomain == "" && eval.MailFrom != "" {
		partsM := strings.Split(eval.MailFrom, "@")
		if len(partsM) == 2 {
			spfDomain = partsM[1]
		}
	}

	return fmt.Sprintf("Received-SPF: %s (%s: domain of %s designates %s as permitted sender) client-ip=%s; envelope-from=%s; helo=%s;",
		eval.SPF.Status,
		authServID,
		spfDomain,
		eval.ClientIP.String(),
		eval.ClientIP.String(),
		eval.MailFrom,
		eval.HELO,
	)
}

// SanitizeUntrustedHeaders strips pre-existing Authentication-Results and Received-SPF headers from untrusted network sources.
func SanitizeUntrustedHeaders(message string) string {
	lines := strings.Split(message, "\n")
	var sanitized []string
	skipContinutation := false

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		lower := strings.ToLower(trimmed)

		if strings.HasPrefix(lower, "authentication-results:") || strings.HasPrefix(lower, "received-spf:") {
			skipContinutation = true
			continue
		}

		if skipContinutation && (strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t")) {
			continue
		}

		skipContinutation = false
		sanitized = append(sanitized, line)
	}

	return strings.Join(sanitized, "\n")
}
