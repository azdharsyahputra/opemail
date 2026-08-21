package bounce

import (
	"regexp"
	"strconv"
	"strings"
)

var enhancedStatusRegex = regexp.MustCompile(`\b([45]\.\d{1,3}\.\d{1,3})\b`)
var replyCodeRegex = regexp.MustCompile(`\b([45]\d{2})\b`)

// ClassifyBounce maps enhanced status codes and SMTP reply text into BounceType and BounceCategory.
func ClassifyBounce(rawText string) *BounceReport {
	enhancedCode := extractEnhancedCode(rawText)
	replyCode := extractReplyCode(rawText)
	lower := strings.ToLower(rawText)

	bType := TypeUnknown
	if strings.HasPrefix(enhancedCode, "5.") || (replyCode >= 500 && replyCode < 600) {
		bType = TypePermanent
	} else if strings.HasPrefix(enhancedCode, "4.") || (replyCode >= 400 && replyCode < 500) {
		bType = TypeTemporary
	}

	category := classifyCategory(enhancedCode, replyCode, lower)

	return &BounceReport{
		Type:           bType,
		Category:       category,
		ReplyCode:      replyCode,
		EnhancedCode:   enhancedCode,
		DiagnosticCode: strings.TrimSpace(rawText),
		IsHardBounce:   bType == TypePermanent,
	}
}

func extractEnhancedCode(text string) string {
	matches := enhancedStatusRegex.FindStringSubmatch(text)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

func extractReplyCode(text string) int {
	matches := replyCodeRegex.FindStringSubmatch(text)
	if len(matches) > 1 {
		val, err := strconv.Atoi(matches[1])
		if err == nil {
			return val
		}
	}
	return 0
}

func classifyCategory(enhancedCode string, replyCode int, lower string) BounceCategory {
	// 1. Check specific enhanced codes (RFC 3463 / RFC 5248)
	switch enhancedCode {
	case "5.1.1":
		return CategoryRecipientUnknown
	case "5.1.2":
		return CategoryDomainUnknown
	case "5.2.2", "4.2.2":
		return CategoryMailboxFull
	case "5.3.4", "5.2.3":
		return CategoryMessageOversized
	case "5.7.1":
		return CategoryPolicyRejection
	case "5.7.0", "5.7.28":
		return CategorySpamRejection
	case "5.7.4", "5.7.10":
		return CategoryTLSFailure
	case "4.4.1", "4.4.2":
		return CategoryConnectionFailure
	case "4.7.1", "4.0.0", "4.4.5":
		return CategoryTemporaryFailure
	}

	// 2. Heuristic string checks
	if strings.Contains(lower, "user unknown") || strings.Contains(lower, "recipient unknown") || strings.Contains(lower, "no such user") || strings.Contains(lower, "mailbox not found") {
		return CategoryRecipientUnknown
	}
	if strings.Contains(lower, "domain not found") || strings.Contains(lower, "host not found") || strings.Contains(lower, "unrouteable address") {
		return CategoryDomainUnknown
	}
	if strings.Contains(lower, "mailbox is full") || strings.Contains(lower, "quota exceeded") || strings.Contains(lower, "user over quota") {
		return CategoryMailboxFull
	}
	if strings.Contains(lower, "message size exceeds") || strings.Contains(lower, "message too large") {
		return CategoryMessageOversized
	}
	if strings.Contains(lower, "spam") || strings.Contains(lower, "blacklisted") || strings.Contains(lower, "blocked by spf") || strings.Contains(lower, "dmarc policy") {
		return CategorySpamRejection
	}
	if strings.Contains(lower, "relay access denied") || strings.Contains(lower, "sender rejected") || strings.Contains(lower, "access denied") {
		return CategoryPolicyRejection
	}
	if strings.Contains(lower, "connection timed out") || strings.Contains(lower, "connection refused") || strings.Contains(lower, "network is unreachable") {
		return CategoryConnectionFailure
	}
	if strings.Contains(lower, "tls handshake") || strings.Contains(lower, "ssl negotiation failed") {
		return CategoryTLSFailure
	}
	if strings.Contains(lower, "try again later") || strings.Contains(lower, "temporary failure") {
		return CategoryTemporaryFailure
	}

	if strings.HasPrefix(enhancedCode, "4.") || (replyCode >= 400 && replyCode < 500) {
		return CategoryTemporaryFailure
	}
	if strings.HasPrefix(enhancedCode, "5.") || (replyCode >= 500 && replyCode < 600) {
		return CategorySystemError
	}

	return CategoryUnknown
}
