package fuzz_test

import (
	"net"
	"strings"
	"testing"

	"github.com/azdharsyahputra/openmail/internal/bounce"
	"github.com/azdharsyahputra/openmail/internal/dns"
	"github.com/azdharsyahputra/openmail/internal/inbound"
	"github.com/azdharsyahputra/openmail/internal/queue"
)

// FUZZ-001: Fuzz Email Address & Domain Parser
func FuzzEmailAndDomain(f *testing.F) {
	seeds := []string{
		"ajar@example.com",
		"user.name+tag@sub.domain.org",
		"admin@localhost",
		"",
		"@",
		"invalid",
		"../../etc/passwd",
		"<script>alert(1)</script>",
		"user@domain..com",
		"a@b.c",
		strings.Repeat("a", 300) + "@domain.com",
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input string) {
		// Validating domain/email must never panic
		_ = dns.ValidateSPFSyntax(input)
	})
}

// FUZZ-006: Fuzz SPF Record Parser
func FuzzSPFParser(f *testing.F) {
	seeds := []string{
		"v=spf1 mx ip4:203.0.113.10 -all",
		"v=spf1 include:_spf.google.com ~all",
		"v=spf1 redirect=example.com",
		"v=spf1 ?all",
		"",
		"v=spf1 ip4:invalid -all",
		"v=spf1 " + strings.Repeat("include:a.com ", 20),
	}

	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, input string) {
		_ = dns.ValidateSPFSyntax(input)
		_ = inbound.EvaluateSPF(net.ParseIP("203.0.113.10"), "sender.com", input)
	})
}

// FUZZ-007: Fuzz DMARC Record Parser
func FuzzDMARCParser(f *testing.F) {
	seeds := []string{
		"v=DMARC1; p=reject; rua=mailto:dmarc@example.com; pct=100; aspf=s",
		"v=DMARC1; p=quarantine; sp=reject; adkim=r",
		"v=DMARC1; p=none",
		"",
		"invalid dmarc text",
		"v=DMARC1; p=invalid_policy",
	}

	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, input string) {
		_, _ = dns.ValidateDMARCSyntax(input)
	})
}

// FUZZ-008: Fuzz Bounce & DSN Parser
func FuzzBounceClassifier(f *testing.F) {
	seeds := []string{
		"550 5.1.1 User unknown in virtual mailbox table",
		"552 5.2.2 Mailbox full",
		"451 4.7.1 Service unavailable",
		"451 4.4.1 Connection timeout",
		"",
		"Random non-standard server reply text without any status codes",
		strings.Repeat("A", 1000),
	}

	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, input string) {
		_ = bounce.ClassifyBounce(input)
	})
}

// FUZZ-009: Fuzz Postfix Queue Output Parser
func FuzzQueueParser(f *testing.F) {
	seeds := []string{
		"Mail queue is empty",
		`-Queue ID- --Size-- ----Arrival Time---- -Sender/Recipient-------
A82F91       1024 Fri Aug 21 22:01:12  sender@example.com
(host mail.receiver.com[198.51.100.1] said: 451 4.7.1 Try again later)
                                         user@gmail.com
-- 1 Kbytes in 1 Request.`,
		"",
		"Corrupted garbage output from postqueue -p\n\n###!@#!@#",
	}

	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, input string) {
		_, _, _ = queue.ParseQueueOutput(input)
	})
}
