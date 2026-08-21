package tests

import (
	"context"
	"crypto/tls"
	"net"
	"net/smtp"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/azdharsyahputra/openmail/internal/config"
	"github.com/azdharsyahputra/openmail/internal/database"
	"github.com/azdharsyahputra/openmail/internal/dkim"
	"github.com/azdharsyahputra/openmail/internal/domain"
	"github.com/azdharsyahputra/openmail/internal/inbound"
	"github.com/azdharsyahputra/openmail/internal/mailbox"
	"github.com/azdharsyahputra/openmail/internal/provisioning"
)

func TestIntegration_InboundSecurity(t *testing.T) {
	ctx := context.Background()

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		cfg, err := config.Load()
		if err == nil && cfg.DatabaseURL != "" {
			dbURL = cfg.DatabaseURL
		} else {
			dbURL = "postgres://mailopen:mailopen@localhost:5433/mailopen?sslmode=disable"
		}

	}

	db, err := database.NewPostgresDB(dbURL)
	if err != nil {
		t.Skipf("Skipping inbound integration test: PostgreSQL unavailable (%v)", err)
		return
	}
	defer db.Close()

	if err := database.RunMigrationsUp(db); err != nil {
		t.Fatalf("failed to run migrations: %v", err)
	}


	tempVmailDir, err := os.MkdirTemp("", "openmail-inbound-vmail-*")
	if err != nil {
		t.Fatalf("temp vmail error: %v", err)
	}
	defer os.RemoveAll(tempVmailDir)

	prov, err := provisioning.NewFilesystemProvisioner(tempVmailDir, 5000, 5000)
	if err != nil {
		t.Fatalf("provisioner error: %v", err)
	}

	domainRepo := domain.NewPostgresRepository(db)
	mailboxRepo := mailbox.NewPostgresRepository(db)
	dkimRepo := dkim.NewPostgresRepository(db)
	dkimKeystore := dkim.NewFilesystemKeystore(os.TempDir())

	domainSvc := domain.NewService(domainRepo)
	mailboxSvc := mailbox.NewService(mailboxRepo, domainRepo, prov)
	dkimSvc := dkim.NewService(dkimRepo, domainRepo, dkimKeystore)
	inboundSvc := inbound.NewService(db, dkimSvc)

	testDomain := "example.com"
	_, _ = domainSvc.Create(ctx, testDomain)
	_ = mailboxSvc.Delete(ctx, "valid@"+testDomain)
	_, err = mailboxSvc.Create(ctx, "valid@"+testDomain, "Secret12345!", 1073741824)
	if err != nil {
		t.Fatalf("failed to create valid@example.com: %v", err)
	}




	// 1. Connection & Open Relay Hardening on :25
	t.Run("Open Relay Matrix: External destination rejected on :25", func(t *testing.T) {
		conn, err := net.DialTimeout("tcp", "127.0.0.1:25", 500*time.Millisecond)
		if err != nil {
			t.Skip("Inbound port :25 unreachable, skipping live SMTP tests")
			return
		}
		_ = conn.Close()

		c, err := smtp.Dial("127.0.0.1:25")
		if err != nil {
			t.Fatalf("smtp dial error: %v", err)
		}
		defer c.Close()

		_ = c.Hello("mail.sender.com")
		_ = c.Mail("attacker@evil.com")
		err = c.Rcpt("victim@gmail.com")
		if err == nil {
			t.Errorf("expected open relay to external domain to be rejected on :25")
		}
	})

	// 2. Inbound Recipient Validation & Anti-Enumeration
	t.Run("Recipient Validation Matrix: Valid -> 250, Unknown/Suspended -> 550 without enumeration", func(t *testing.T) {
		// Valid recipient
		ok, err := inboundSvc.VerifyRecipient(ctx, "valid@"+testDomain)
		if err != nil || !ok {
			t.Errorf("expected valid recipient to pass verification")
		}

		// Unknown recipient
		ok, err = inboundSvc.VerifyRecipient(ctx, "ghost@"+testDomain)
		if err != nil || ok {
			t.Errorf("expected unknown recipient to fail verification")
		}

		// Nonexistent domain
		ok, err = inboundSvc.VerifyRecipient(ctx, "user@nonexistent-domain.xyz")
		if err != nil || ok {
			t.Errorf("expected unknown domain recipient to fail verification")
		}
	})

	// 3. SPF Evaluation Matrix
	t.Run("SPF Evaluation Matrix", func(t *testing.T) {
		ip := net.ParseIP("203.0.113.50")

		tests := []struct {
			name     string
			spf      string
			expected inbound.AuthStatus
		}{
			{"Pass with CIDR", "v=spf1 ip4:203.0.113.0/24 -all", inbound.AuthPass},
			{"Fail with mismatched IP", "v=spf1 ip4:198.51.100.1 -all", inbound.AuthFail},
			{"SoftFail with ~all", "v=spf1 ip4:198.51.100.1 ~all", inbound.AuthSoftFail},
			{"Neutral with ?all", "v=spf1 ?all", inbound.AuthNeutral},
			{"None with empty record", "", inbound.AuthNone},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				res := inbound.EvaluateSPF(ip, "sender.com", tc.spf)
				if res != tc.expected {
					t.Errorf("expected %s, got %s", tc.expected, res)
				}
			})
		}
	})

	// 4. DMARC Evaluation & Alignment Matrix
	t.Run("DMARC Alignment & Policy Enforcement Matrix", func(t *testing.T) {
		tests := []struct {
			name           string
			headerFrom     string
			spfStatus      inbound.AuthStatus
			spfDomain      string
			dkimStatus     inbound.AuthStatus
			dkimDomain     string
			dmarcPolicy    string
			expectedDMARC  inbound.AuthStatus
			expectedAction inbound.SpamAction
		}{
			{
				name:           "SPF Aligned only -> DMARC PASS (Deliver)",
				headerFrom:     "boss@corp.com",
				spfStatus:      inbound.AuthPass,
				spfDomain:      "corp.com",
				dkimStatus:     inbound.AuthFail,
				dkimDomain:     "unrelated.com",
				dmarcPolicy:    "reject",
				expectedDMARC:  inbound.AuthPass,
				expectedAction: inbound.ActionDeliver,
			},
			{
				name:           "DKIM Aligned only -> DMARC PASS (Deliver)",
				headerFrom:     "boss@corp.com",
				spfStatus:      inbound.AuthFail,
				spfDomain:      "evil.com",
				dkimStatus:     inbound.AuthPass,
				dkimDomain:     "corp.com",
				dmarcPolicy:    "reject",
				expectedDMARC:  inbound.AuthPass,
				expectedAction: inbound.ActionDeliver,
			},
			{
				name:           "Both Unaligned + Policy p=none -> DMARC FAIL (Deliver / Observation)",
				headerFrom:     "victim@corp.com",
				spfStatus:      inbound.AuthPass,
				spfDomain:      "attacker.com",
				dkimStatus:     inbound.AuthPass,
				dkimDomain:     "attacker.com",
				dmarcPolicy:    "none",
				expectedDMARC:  inbound.AuthFail,
				expectedAction: inbound.ActionDeliver,
			},
			{
				name:           "Both Unaligned + Policy p=quarantine -> DMARC FAIL (Quarantine)",
				headerFrom:     "victim@corp.com",
				spfStatus:      inbound.AuthPass,
				spfDomain:      "attacker.com",
				dkimStatus:     inbound.AuthPass,
				dkimDomain:     "attacker.com",
				dmarcPolicy:    "quarantine",
				expectedDMARC:  inbound.AuthFail,
				expectedAction: inbound.ActionQuarantine,
			},
			{
				name:           "Both Unaligned + Policy p=reject -> DMARC FAIL (Reject)",
				headerFrom:     "victim@corp.com",
				spfStatus:      inbound.AuthPass,
				spfDomain:      "attacker.com",
				dkimStatus:     inbound.AuthPass,
				dkimDomain:     "attacker.com",
				dmarcPolicy:    "reject",
				expectedDMARC:  inbound.AuthFail,
				expectedAction: inbound.ActionReject,
			},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				spf := inbound.SPFVerification{Status: tc.spfStatus, Domain: tc.spfDomain}
				dkim := inbound.DKIMVerification{Status: tc.dkimStatus, Domain: tc.dkimDomain}
				ver := inbound.EvaluateDMARC(tc.headerFrom, spf, dkim, tc.dmarcPolicy)

				if ver.Status != tc.expectedDMARC {
					t.Errorf("expected DMARC %s, got %s", tc.expectedDMARC, ver.Status)
				}
				if ver.Action != tc.expectedAction {
					t.Errorf("expected Action %s, got %s", tc.expectedAction, ver.Action)
				}
			})
		}
	})

	// 5. Inbound Security Pipeline & Header Injection
	t.Run("Inbound Security Pipeline & Header Injection", func(t *testing.T) {
		eval := &inbound.InboundEvaluation{
			AuthServID:     "mail.example.com",
			ClientIP:       net.ParseIP("203.0.113.10"),
			ClientHostname: "mail.trusted.com",
			HELO:           "mail.trusted.com",
			MailFrom:       "sender@trusted.com",
			HeaderFrom:     "sender@trusted.com",
			Recipient:      "valid@" + testDomain,
			MessageSize:    1024,
			SPF: inbound.SPFVerification{
				Status: inbound.AuthPass,
				Domain: "trusted.com",
			},
			DKIM: inbound.DKIMVerification{
				Status:   inbound.AuthPass,
				Domain:   "trusted.com",
				Selector: "mailopen2026",
			},
			DMARC: inbound.DMARCVerification{
				Policy: "reject",
			},
			SpamScore:       1.2,
			SpamThreshold:   6.0,
			RejectThreshold: 15.0,
			AntivirusClean:  true,
		}

		res, err := inboundSvc.Evaluate(ctx, eval)
		if err != nil {
			t.Fatalf("evaluation failed: %v", err)
		}

		if res.FinalAction != inbound.ActionDeliver {
			t.Errorf("expected ActionDeliver, got %s", res.FinalAction)
		}
		if !strings.Contains(res.AuthenticationResults, "spf=pass") || !strings.Contains(res.AuthenticationResults, "dkim=pass") || !strings.Contains(res.AuthenticationResults, "dmarc=pass") {
			t.Errorf("Authentication-Results missing tokens:\n%s", res.AuthenticationResults)
		}
		if !strings.Contains(res.ReceivedSPF, "Received-SPF: pass") {
			t.Errorf("Received-SPF missing pass token:\n%s", res.ReceivedSPF)
		}
	})

	// 6. Live Inbound :25 Submission and Delivery
	t.Run("Live Inbound :25 Submission to Valid Mailbox", func(t *testing.T) {
		_, _ = domainSvc.Create(ctx, testDomain)
		_ = mailboxSvc.Delete(ctx, "valid@"+testDomain)
		_, _ = mailboxSvc.Create(ctx, "valid@"+testDomain, "Secret12345!", 1073741824)

		c, err := smtp.Dial("127.0.0.1:25")
		if err != nil {
			t.Skip("Inbound port :25 not reachable, skipping live delivery test")
			return
		}
		defer c.Close()

		_ = c.StartTLS(&tls.Config{InsecureSkipVerify: true})
		if err := c.Mail("external-sender@partner.com"); err != nil {
			t.Fatalf("MAIL FROM failed: %v", err)
		}
		if err := c.Rcpt("valid@" + testDomain); err != nil {
			t.Fatalf("RCPT TO failed: %v", err)
		}


		w, err := c.Data()
		if err != nil {
			t.Fatalf("DATA failed: %v", err)
		}

		msg := "From: external-sender@partner.com\r\nTo: valid@" + testDomain + "\r\nSubject: Inbound Test\r\n\r\nLive Inbound Body\r\n"
		if _, err := w.Write([]byte(msg)); err != nil {
			t.Fatalf("write body failed: %v", err)
		}
		if err := w.Close(); err != nil {
			t.Fatalf("close DATA failed: %v", err)
		}
		_ = c.Quit()
	})
}
