package bounce

import (
	"bufio"
	"strings"
)

// ParseDSN parses an RFC 3464 Delivery Status Notification message.
func ParseDSN(rawMessage string) *BounceReport {
	scanner := bufio.NewScanner(strings.NewReader(rawMessage))
	var originalRcpt, remoteMTA, diagCode, statusHeader string

	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		lower := strings.ToLower(trimmed)

		if strings.HasPrefix(lower, "final-recipient:") || strings.HasPrefix(lower, "original-recipient:") {
			parts := strings.SplitN(trimmed, ";", 2)
			if len(parts) == 2 {
				originalRcpt = strings.TrimSpace(parts[1])
			}
		} else if strings.HasPrefix(lower, "remote-mta:") {
			parts := strings.SplitN(trimmed, ";", 2)
			if len(parts) == 2 {
				remoteMTA = strings.TrimSpace(parts[1])
			}
		} else if strings.HasPrefix(lower, "diagnostic-code:") {
			parts := strings.SplitN(trimmed, ";", 2)
			if len(parts) == 2 {
				diagCode = strings.TrimSpace(parts[1])
			} else {
				diagCode = strings.TrimSpace(strings.TrimPrefix(trimmed, "Diagnostic-Code:"))
			}
		} else if strings.HasPrefix(lower, "status:") {
			statusHeader = strings.TrimSpace(strings.TrimPrefix(trimmed, "Status:"))
		}
	}

	analysisText := diagCode
	if analysisText == "" {
		analysisText = statusHeader
	}
	if analysisText == "" {
		analysisText = rawMessage
	}

	report := ClassifyBounce(analysisText)
	report.OriginalRecipient = originalRcpt
	report.RemoteMTA = remoteMTA
	return report
}
