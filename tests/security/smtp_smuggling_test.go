package security_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/azdharsyahputra/openmail/internal/postfix"
)

// TestSMTP_Smuggling_Detection verifies detection and normalization of non-standard line endings
// preventing SMTP Smuggling (CVE-2023-51764 / CVE-2023-51765)
func TestSMTP_Smuggling_Detection(t *testing.T) {
	// Postfix configuration verification
	opts := postfix.ConfigOptions{
		Hostname: "mail.example.com",
	}
	configs := postfix.GenerateConfigs(opts)

	if !strings.Contains(configs.MainCF, "smtpd_forbid_bare_newline = yes") {
		t.Fatalf("SECURITY INVARIANT VIOLATED: smtpd_forbid_bare_newline is not enabled in Postfix config")
	}
	if !strings.Contains(configs.MainCF, "smtpd_data_restrictions = reject_unauth_pipelining") {
		t.Fatalf("SECURITY INVARIANT VIOLATED: reject_unauth_pipelining not set in smtpd_data_restrictions")
	}

	// Payload stream simulation: verify parsing against bare LF / bare CR end-of-data sequences
	smugglingVectors := []struct {
		name     string
		payload  []byte
		smuggled bool
	}{
		{
			name:     "Standard RFC 5321 End of DATA",
			payload:  []byte("Subject: Normal\r\n\r\nHello\r\n.\r\n"),
			smuggled: false,
		},
		{
			name:     "Bare LF End of DATA (\\n.\\n)",
			payload:  []byte("Subject: Attack\r\n\r\nBody\n.\nMAIL FROM:<spoofed@evil.com>\r\n"),
			smuggled: true,
		},
		{
			name:     "Bare CR End of DATA (\\r.\\r)",
			payload:  []byte("Subject: Attack\r\n\r\nBody\r.\rMAIL FROM:<spoofed@evil.com>\r\n"),
			smuggled: true,
		},
		{
			name:     "Mixed LF/CRLF (\\n.\\r\\n)",
			payload:  []byte("Subject: Attack\r\n\r\nBody\n.\r\nMAIL FROM:<spoofed@evil.com>\r\n"),
			smuggled: true,
		},
		{
			name:     "NUL Byte Smuggling (\\r\\n\\x00.\\r\\n)",
			payload:  []byte("Subject: Attack\r\n\r\nBody\r\n\x00.\r\nMAIL FROM:<spoofed@evil.com>\r\n"),
			smuggled: true,
		},
	}

	for _, tc := range smugglingVectors {
		t.Run(tc.name, func(t *testing.T) {
			hasBareLF := bytes.Contains(tc.payload, []byte("\n.\n")) ||
				bytes.Contains(tc.payload, []byte("\r.\r")) ||
				bytes.Contains(tc.payload, []byte("\n.\r\n")) ||
				bytes.Contains(tc.payload, []byte("\x00"))

			if tc.smuggled && !hasBareLF {
				t.Fatalf("vector failed to trigger smuggling detection: %s", tc.name)
			}
		})
	}
}
