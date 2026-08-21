package inbound_test

import (
	"net"
	"strings"
	"testing"

	"github.com/azdharsyahputra/openmail/internal/inbound"
)

func TestSPFEvaluation(t *testing.T) {
	clientIP := net.ParseIP("203.0.113.10")

	t.Run("SPF Pass with matched ip4", func(t *testing.T) {
		record := "v=spf1 ip4:203.0.113.10 -all"
		status := inbound.EvaluateSPF(clientIP, "sender.com", record)
		if status != inbound.AuthPass {
			t.Errorf("expected AuthPass, got %s", status)
		}
	})

	t.Run("SPF Fail with mismatched ip4 and -all", func(t *testing.T) {
		record := "v=spf1 ip4:198.51.100.1 -all"
		status := inbound.EvaluateSPF(clientIP, "sender.com", record)
		if status != inbound.AuthFail {
			t.Errorf("expected AuthFail, got %s", status)
		}
	})

	t.Run("SPF SoftFail with ~all", func(t *testing.T) {
		record := "v=spf1 ip4:198.51.100.1 ~all"
		status := inbound.EvaluateSPF(clientIP, "sender.com", record)
		if status != inbound.AuthSoftFail {
			t.Errorf("expected AuthSoftFail, got %s", status)
		}
	})

	t.Run("SPF None when no record", func(t *testing.T) {
		status := inbound.EvaluateSPF(clientIP, "sender.com", "")
		if status != inbound.AuthNone {
			t.Errorf("expected AuthNone, got %s", status)
		}
	})
}

func TestDMARCAlignmentAndPolicyMatrix(t *testing.T) {
	headerFrom := "user@example.com"

	t.Run("SPF Aligned + DKIM Fail -> DMARC PASS", func(t *testing.T) {
		spf := inbound.SPFVerification{
			Status: inbound.AuthPass,
			Domain: "example.com",
		}
		dkim := inbound.DKIMVerification{
			Status: inbound.AuthFail,
			Domain: "other.com",
		}

		res := inbound.EvaluateDMARC(headerFrom, spf, dkim, "reject")
		if res.Status != inbound.AuthPass {
			t.Errorf("expected DMARC PASS, got %s", res.Status)
		}
		if res.Action != inbound.ActionDeliver {
			t.Errorf("expected ActionDeliver, got %s", res.Action)
		}
	})

	t.Run("DKIM Aligned + SPF Fail -> DMARC PASS", func(t *testing.T) {
		spf := inbound.SPFVerification{
			Status: inbound.AuthFail,
			Domain: "unrelated.org",
		}
		dkim := inbound.DKIMVerification{
			Status: inbound.AuthPass,
			Domain: "example.com",
		}

		res := inbound.EvaluateDMARC(headerFrom, spf, dkim, "reject")
		if res.Status != inbound.AuthPass {
			t.Errorf("expected DMARC PASS, got %s", res.Status)
		}
		if res.Action != inbound.ActionDeliver {
			t.Errorf("expected ActionDeliver, got %s", res.Action)
		}
	})

	t.Run("Both Fail + Policy p=none -> Deliver (Observation)", func(t *testing.T) {
		spf := inbound.SPFVerification{Status: inbound.AuthFail, Domain: "evil.com"}
		dkim := inbound.DKIMVerification{Status: inbound.AuthFail, Domain: "evil.com"}

		res := inbound.EvaluateDMARC(headerFrom, spf, dkim, "none")
		if res.Status != inbound.AuthFail {
			t.Errorf("expected DMARC Fail, got %s", res.Status)
		}
		if res.Action != inbound.ActionDeliver {
			t.Errorf("expected ActionDeliver on p=none, got %s", res.Action)
		}
	})

	t.Run("Both Fail + Policy p=quarantine -> Quarantine", func(t *testing.T) {
		spf := inbound.SPFVerification{Status: inbound.AuthFail, Domain: "evil.com"}
		dkim := inbound.DKIMVerification{Status: inbound.AuthFail, Domain: "evil.com"}

		res := inbound.EvaluateDMARC(headerFrom, spf, dkim, "quarantine")
		if res.Status != inbound.AuthFail {
			t.Errorf("expected DMARC Fail, got %s", res.Status)
		}
		if res.Action != inbound.ActionQuarantine {
			t.Errorf("expected ActionQuarantine on p=quarantine, got %s", res.Action)
		}
	})

	t.Run("Both Fail + Policy p=reject -> Reject", func(t *testing.T) {
		spf := inbound.SPFVerification{Status: inbound.AuthFail, Domain: "evil.com"}
		dkim := inbound.DKIMVerification{Status: inbound.AuthFail, Domain: "evil.com"}

		res := inbound.EvaluateDMARC(headerFrom, spf, dkim, "reject")
		if res.Status != inbound.AuthFail {
			t.Errorf("expected DMARC Fail, got %s", res.Status)
		}
		if res.Action != inbound.ActionReject {
			t.Errorf("expected ActionReject on p=reject, got %s", res.Action)
		}
	})
}

func TestUnifiedInboundSecurityEvaluation(t *testing.T) {
	t.Run("Malware detected -> Reject", func(t *testing.T) {
		eval := &inbound.InboundEvaluation{
			AntivirusClean: false,
			VirusName:      "EICAR-Test-Signature",
		}
		err := inbound.EvaluateInboundSecurity(eval)
		if err == nil || eval.FinalAction != inbound.ActionReject {
			t.Errorf("expected malware rejection, got action: %s, err: %v", eval.FinalAction, err)
		}
	})

	t.Run("Oversized message (> 25MB) -> Reject", func(t *testing.T) {
		eval := &inbound.InboundEvaluation{
			AntivirusClean: true,
			MessageSize:    30 * 1024 * 1024,
		}
		err := inbound.EvaluateInboundSecurity(eval)
		if err == nil || eval.FinalAction != inbound.ActionReject {
			t.Errorf("expected oversized message rejection, got action: %s, err: %v", eval.FinalAction, err)
		}
	})

	t.Run("High Spam Score >= Reject Threshold -> Reject", func(t *testing.T) {
		eval := &inbound.InboundEvaluation{
			AntivirusClean:  true,
			SpamScore:       18.5,
			SpamThreshold:   6.0,
			RejectThreshold: 15.0,
		}
		err := inbound.EvaluateInboundSecurity(eval)
		if err == nil || eval.FinalAction != inbound.ActionReject {
			t.Errorf("expected spam rejection, got action: %s, err: %v", eval.FinalAction, err)
		}
	})

	t.Run("Moderate Spam Score >= Spam Threshold -> Junk", func(t *testing.T) {
		eval := &inbound.InboundEvaluation{
			AntivirusClean:  true,
			SpamScore:       7.5,
			SpamThreshold:   6.0,
			RejectThreshold: 15.0,
		}
		err := inbound.EvaluateInboundSecurity(eval)
		if err != nil || eval.FinalAction != inbound.ActionJunk {
			t.Errorf("expected junk action for spam score 7.5, got action: %s, err: %v", eval.FinalAction, err)
		}
	})
}

func TestHeaderInjectionAndSanitization(t *testing.T) {
	eval := &inbound.InboundEvaluation{
		AuthServID: "mail.example.com",
		ClientIP:   net.ParseIP("203.0.113.10"),
		MailFrom:   "sender@example.com",
		HeaderFrom: "sender@example.com",
		SPF: inbound.SPFVerification{
			Status: inbound.AuthPass,
			Domain: "example.com",
		},
		DKIM: inbound.DKIMVerification{
			Status:   inbound.AuthPass,
			Domain:   "example.com",
			Selector: "mailopen2026",
		},
		DMARC: inbound.DMARCVerification{
			Status: inbound.AuthPass,
			Policy: "none",
		},
	}

	authResults := inbound.BuildAuthenticationResults(eval)
	if !strings.Contains(authResults, "spf=pass") || !strings.Contains(authResults, "dkim=pass") || !strings.Contains(authResults, "dmarc=pass") {
		t.Errorf("Authentication-Results missing expected tokens:\n%s", authResults)
	}

	receivedSPF := inbound.BuildReceivedSPF(eval)
	if !strings.Contains(receivedSPF, "Received-SPF: pass") {
		t.Errorf("Received-SPF missing pass token:\n%s", receivedSPF)
	}

	fakeMessage := "From: attacker@evil.com\nAuthentication-Results: fake.com; dkim=pass\nSubject: Spoofed\n\nBody"
	sanitized := inbound.SanitizeUntrustedHeaders(fakeMessage)
	if strings.Contains(sanitized, "fake.com") {
		t.Errorf("expected untrusted Authentication-Results to be stripped")
	}
}
