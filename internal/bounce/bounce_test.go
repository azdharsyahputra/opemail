package bounce_test

import (
	"testing"

	"github.com/azdharsyahputra/openmail/internal/bounce"
)

func TestBounceClassification(t *testing.T) {
	tests := []struct {
		name             string
		input            string
		expectedType     bounce.BounceType
		expectedCategory bounce.BounceCategory
		expectedCode     string
	}{
		{
			name:             "User Unknown 5.1.1",
			input:            "550 5.1.1 <user@example.com>: Recipient address rejected: User unknown in virtual mailbox table",
			expectedType:     bounce.TypePermanent,
			expectedCategory: bounce.CategoryRecipientUnknown,
			expectedCode:     "5.1.1",
		},
		{
			name:             "Mailbox Full 5.2.2",
			input:            "552 5.2.2 <user@example.com>: Mailbox is full / quota exceeded",
			expectedType:     bounce.TypePermanent,
			expectedCategory: bounce.CategoryMailboxFull,
			expectedCode:     "5.2.2",
		},
		{
			name:             "Domain Unknown 5.1.2",
			input:            "550 5.1.2 <user@invalid-domain-xyz.com>: Host or domain name not found",
			expectedType:     bounce.TypePermanent,
			expectedCategory: bounce.CategoryDomainUnknown,
			expectedCode:     "5.1.2",
		},
		{
			name:             "Policy Rejection 5.7.1",
			input:            "554 5.7.1 <victim@gmail.com>: Relay access denied",
			expectedType:     bounce.TypePermanent,
			expectedCategory: bounce.CategoryPolicyRejection,
			expectedCode:     "5.7.1",
		},
		{
			name:             "Spam Rejection 5.7.0",
			input:            "550 5.7.0 Message rejected due to spam content detection",
			expectedType:     bounce.TypePermanent,
			expectedCategory: bounce.CategorySpamRejection,
			expectedCode:     "5.7.0",
		},
		{
			name:             "Connection Timeout 4.4.1",
			input:            "451 4.4.1 Connection timed out with remote host",
			expectedType:     bounce.TypeTemporary,
			expectedCategory: bounce.CategoryConnectionFailure,
			expectedCode:     "4.4.1",
		},
		{
			name:             "Temporary Remote Failure 4.7.1",
			input:            "451 4.7.1 Try again later; rate limit reached",
			expectedType:     bounce.TypeTemporary,
			expectedCategory: bounce.CategoryTemporaryFailure,
			expectedCode:     "4.7.1",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			report := bounce.ClassifyBounce(tc.input)
			if report.Type != tc.expectedType {
				t.Errorf("expected type %s, got %s", tc.expectedType, report.Type)
			}
			if report.Category != tc.expectedCategory {
				t.Errorf("expected category %s, got %s", tc.expectedCategory, report.Category)
			}
			if report.EnhancedCode != tc.expectedCode {
				t.Errorf("expected enhanced code %s, got %s", tc.expectedCode, report.EnhancedCode)
			}
		})
	}
}

func TestParseDSN(t *testing.T) {
	dsn := `Final-Recipient: rfc822; ghost@example.com
Action: failed
Status: 5.1.1
Remote-MTA: dns; mail.example.com
Diagnostic-Code: smtp; 550 5.1.1 User unknown
`
	report := bounce.ParseDSN(dsn)
	if report.OriginalRecipient != "ghost@example.com" {
		t.Errorf("expected recipient ghost@example.com, got %s", report.OriginalRecipient)
	}
	if report.Type != bounce.TypePermanent || report.Category != bounce.CategoryRecipientUnknown {
		t.Errorf("expected permanent recipient_unknown, got %s / %s", report.Type, report.Category)
	}
}
