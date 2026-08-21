package dns

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

var (
	ErrInvalidDMARCSyntax = errors.New("invalid dmarc syntax")
)

type DMARCPolicy struct {
	Policy       string // none, quarantine, reject
	SubPolicy    string // none, quarantine, reject
	RUA          string // aggregate report mailto uri
	RUF          string // forensic report mailto uri
	Percentage   int    // 1-100
	ADKIM        string // r (relaxed), s (strict)
	ASPF         string // r (relaxed), s (strict)
	ReportFormat string // afrf
}

// ValidateDMARCSyntax validates DMARC record syntax according to RFC 7489.
func ValidateDMARCSyntax(dmarc string) (*DMARCPolicy, error) {
	dmarc = strings.TrimSpace(dmarc)
	dmarc = strings.Trim(dmarc, "\"")

	tags := make(map[string]string)
	parts := strings.Split(dmarc, ";")

	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		kv := strings.SplitN(p, "=", 2)
		if len(kv) == 2 {
			k := strings.TrimSpace(strings.ToLower(kv[0]))
			v := strings.TrimSpace(kv[1])
			tags[k] = v
		}
	}

	v, ok := tags["v"]
	if !ok || strings.ToUpper(v) != "DMARC1" {
		return nil, fmt.Errorf("%w: record must start with 'v=DMARC1'", ErrInvalidDMARCSyntax)
	}

	policy, ok := tags["p"]
	if !ok || policy == "" {
		return nil, fmt.Errorf("%w: missing required 'p' policy tag", ErrInvalidDMARCSyntax)
	}
	policy = strings.ToLower(policy)
	if policy != "none" && policy != "quarantine" && policy != "reject" {
		return nil, fmt.Errorf("%w: invalid policy '%s' (must be none, quarantine, or reject)", ErrInvalidDMARCSyntax, policy)
	}

	parsed := &DMARCPolicy{
		Policy:     policy,
		Percentage: 100,
		ADKIM:      "r",
		ASPF:       "r",
	}

	if sp, ok := tags["sp"]; ok {
		sp = strings.ToLower(sp)
		if sp != "none" && sp != "quarantine" && sp != "reject" {
			return nil, fmt.Errorf("%w: invalid subdomain policy 'sp=%s'", ErrInvalidDMARCSyntax, sp)
		}
		parsed.SubPolicy = sp
	}

	if rua, ok := tags["rua"]; ok {
		if !strings.HasPrefix(strings.ToLower(rua), "mailto:") {
			return nil, fmt.Errorf("%w: invalid rua URI '%s' (must start with mailto:)", ErrInvalidDMARCSyntax, rua)
		}
		parsed.RUA = rua
	}

	if ruf, ok := tags["ruf"]; ok {
		if !strings.HasPrefix(strings.ToLower(ruf), "mailto:") {
			return nil, fmt.Errorf("%w: invalid ruf URI '%s' (must start with mailto:)", ErrInvalidDMARCSyntax, ruf)
		}
		parsed.RUF = ruf
	}

	if pctStr, ok := tags["pct"]; ok {
		pct, err := strconv.Atoi(pctStr)
		if err != nil || pct < 0 || pct > 100 {
			return nil, fmt.Errorf("%w: invalid pct '%s' (must be integer 0-100)", ErrInvalidDMARCSyntax, pctStr)
		}
		parsed.Percentage = pct
	}

	if adkim, ok := tags["adkim"]; ok {
		adkim = strings.ToLower(adkim)
		if adkim != "r" && adkim != "s" {
			return nil, fmt.Errorf("%w: invalid adkim '%s' (must be r or s)", ErrInvalidDMARCSyntax, adkim)
		}
		parsed.ADKIM = adkim
	}

	if aspf, ok := tags["aspf"]; ok {
		aspf = strings.ToLower(aspf)
		if aspf != "r" && aspf != "s" {
			return nil, fmt.Errorf("%w: invalid aspf '%s' (must be r or s)", ErrInvalidDMARCSyntax, aspf)
		}
		parsed.ASPF = aspf
	}

	return parsed, nil
}

// GenerateDefaultDMARC returns the recommended initial DMARC policy for a domain.
func GenerateDefaultDMARC(domain string) string {
	return fmt.Sprintf("v=DMARC1; p=none; rua=mailto:dmarc@%s", domain)
}
