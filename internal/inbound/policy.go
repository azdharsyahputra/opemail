package inbound

import (
	"fmt"
	"net"
	"strings"
)

// EvaluateSPF performs local evaluation of SPF terms according to RFC 7208.
func EvaluateSPF(clientIP net.IP, senderDomain string, spfRecord string) AuthStatus {
	if spfRecord == "" {
		return AuthNone
	}

	spfRecord = strings.TrimSpace(strings.Trim(spfRecord, "\""))
	if !strings.HasPrefix(spfRecord, "v=spf1") {
		return AuthPermError
	}

	terms := strings.Fields(spfRecord)
	for _, term := range terms[1:] {
		qualifier := "+"
		if strings.HasPrefix(term, "+") || strings.HasPrefix(term, "-") || strings.HasPrefix(term, "~") || strings.HasPrefix(term, "?") {
			qualifier = term[:1]
			term = term[1:]
		}

		lower := strings.ToLower(term)
		var matched bool

		if lower == "all" {
			matched = true
		} else if strings.HasPrefix(lower, "ip4:") {
			ipStr := lower[4:]
			if strings.Contains(ipStr, "/") {
				_, ipNet, err := net.ParseCIDR(ipStr)
				if err == nil && ipNet.Contains(clientIP) {
					matched = true
				}
			} else {
				targetIP := net.ParseIP(ipStr)
				if targetIP != nil && targetIP.Equal(clientIP) {
					matched = true
				}
			}
		} else if strings.HasPrefix(lower, "ip6:") {
			ipStr := lower[4:]
			if strings.Contains(ipStr, "/") {
				_, ipNet, err := net.ParseCIDR(ipStr)
				if err == nil && ipNet.Contains(clientIP) {
					matched = true
				}
			} else {
				targetIP := net.ParseIP(ipStr)
				if targetIP != nil && targetIP.Equal(clientIP) {
					matched = true
				}
			}
		} else if lower == "mx" || lower == "a" {
			// In local evaluation without real DNS, matches local network
			matched = false
		}

		if matched {
			switch qualifier {
			case "+":
				return AuthPass
			case "-":
				return AuthFail
			case "~":
				return AuthSoftFail
			case "?":
				return AuthNeutral
			}
		}
	}

	return AuthNeutral
}

// IsDomainAligned checks RFC 7489 identifier alignment between authenticated domain and From header domain.
func IsDomainAligned(authDomain, headerFromDomain string, strict bool) bool {
	authDomain = strings.ToLower(strings.TrimSpace(authDomain))
	headerFromDomain = strings.ToLower(strings.TrimSpace(headerFromDomain))

	if authDomain == "" || headerFromDomain == "" {
		return false
	}

	if strict {
		return authDomain == headerFromDomain
	}

	// Relaxed alignment: same base domain (e.g. mail.example.com aligns with example.com)
	if authDomain == headerFromDomain {
		return true
	}
	if strings.HasSuffix(authDomain, "."+headerFromDomain) || strings.HasSuffix(headerFromDomain, "."+authDomain) {
		return true
	}

	return false
}

// EvaluateDMARC computes DMARC status and action based on SPF and DKIM alignment.
func EvaluateDMARC(headerFrom string, spf SPFVerification, dkim DKIMVerification, dmarcPolicy string) DMARCVerification {
	fromDomain := headerFrom
	if strings.Contains(fromDomain, "@") {
		parts := strings.Split(fromDomain, "@")
		fromDomain = parts[len(parts)-1]
	}
	fromDomain = strings.ToLower(strings.TrimSpace(fromDomain))

	policy := "none"
	if dmarcPolicy != "" {
		policy = strings.ToLower(strings.TrimSpace(dmarcPolicy))
	}

	spfAligned := (spf.Status == AuthPass) && IsDomainAligned(spf.Domain, fromDomain, false)
	dkimAligned := (dkim.Status == AuthPass) && IsDomainAligned(dkim.Domain, fromDomain, false)

	result := DMARCVerification{
		Policy:      policy,
		SPFAligned:  spfAligned,
		DKIMAligned: dkimAligned,
	}

	if spfAligned || dkimAligned {
		result.Status = AuthPass
		result.Action = ActionDeliver
		result.Reason = "DMARC pass: identifier alignment satisfied"
	} else {
		result.Status = AuthFail
		switch policy {
		case "reject":
			result.Action = ActionReject
			result.Reason = "DMARC fail: policy is p=reject"
		case "quarantine":
			result.Action = ActionQuarantine
			result.Reason = "DMARC fail: policy is p=quarantine"
		default:
			result.Action = ActionDeliver
			result.Reason = "DMARC fail: policy is p=none (observation mode)"
		}
	}

	return result
}

// EvaluateInboundSecurity executes the unified inbound policy pipeline.
func EvaluateInboundSecurity(eval *InboundEvaluation) error {
	// 1. Antivirus / Malware Check
	if !eval.AntivirusClean {
		eval.FinalAction = ActionReject
		return fmt.Errorf("%w: %s", ErrMalwareDetected, eval.VirusName)
	}

	// 2. Message Size Check
	if eval.MessageSize > 0 && eval.MessageSize > 26214400 { // 25MB default
		eval.FinalAction = ActionReject
		return ErrMessageOversized
	}

	// 3. Spam Threshold Check
	if eval.RejectThreshold > 0 && eval.SpamScore >= eval.RejectThreshold {
		eval.FinalAction = ActionReject
		eval.IsSpam = true
		return fmt.Errorf("message rejected: spam score %.1f exceeds reject threshold %.1f", eval.SpamScore, eval.RejectThreshold)
	}

	if eval.SpamThreshold > 0 && eval.SpamScore >= eval.SpamThreshold {
		eval.FinalAction = ActionJunk
		eval.IsSpam = true
		return nil
	}

	// 4. DMARC Action Check
	if eval.DMARC.Action == ActionReject {
		eval.FinalAction = ActionReject
		return fmt.Errorf("%w (%s)", ErrDMARCRejected, eval.DMARC.Reason)
	}
	if eval.DMARC.Action == ActionQuarantine {
		eval.FinalAction = ActionQuarantine
		return nil
	}

	eval.FinalAction = ActionDeliver
	return nil
}
