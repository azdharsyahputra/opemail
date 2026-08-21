package tests

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/azdharsyahputra/openmail/internal/dns"
)

func TestIntegration_DNS(t *testing.T) {
	t.Run("SPF Syntax Validation Matrix", func(t *testing.T) {
		validSPFs := []string{
			"v=spf1 mx ~all",
			"v=spf1 mx ip4:203.0.113.10 -all",
			"v=spf1 include:_spf.google.com ~all",
			"v=spf1 a mx ip6:2001:db8::/32 ?all",
		}

		for _, spf := range validSPFs {
			if err := dns.ValidateSPFSyntax(spf); err != nil {
				t.Errorf("expected SPF '%s' to be valid, got: %v", spf, err)
			}
		}

		invalidSPFs := []string{
			"",
			"v=spf2 mx ~all",
			"mx ~all",
			"v=spf1 invalidmechanism ~all",
		}

		for _, spf := range invalidSPFs {
			if err := dns.ValidateSPFSyntax(spf); err == nil {
				t.Errorf("expected SPF '%s' to be invalid, but passed", spf)
			}
		}
	})

	t.Run("DMARC Syntax Validation Matrix", func(t *testing.T) {
		validDMARCs := []string{
			"v=DMARC1; p=none",
			"v=DMARC1; p=quarantine; pct=100; rua=mailto:dmarc@example.com",
			"v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s; rua=mailto:dmarc@example.com",
		}

		for _, dmarc := range validDMARCs {
			policy, err := dns.ValidateDMARCSyntax(dmarc)
			if err != nil {
				t.Errorf("expected DMARC '%s' to be valid, got: %v", dmarc, err)
			}
			if policy.Policy == "" {
				t.Errorf("expected non-empty policy")
			}
		}

		invalidDMARCs := []string{
			"",
			"v=DMARC2; p=none",
			"p=none",
			"v=DMARC1; p=invalidpolicy",
			"v=DMARC1; p=reject; rua=invalid-uri",
			"v=DMARC1; p=reject; pct=200",
		}

		for _, dmarc := range invalidDMARCs {
			if _, err := dns.ValidateDMARCSyntax(dmarc); err == nil {
				t.Errorf("expected DMARC '%s' to be invalid, but passed", dmarc)
			}
		}
	})

	t.Run("Domain Doctor Report Execution", func(t *testing.T) {
		mockTXTLookup := func(host string) ([]string, error) {
			if host == "example.com" {
				return []string{"v=spf1 mx ~all"}, nil
			}
			if host == "_dmarc.example.com" {
				return []string{"v=DMARC1; p=none; rua=mailto:dmarc@example.com"}, nil
			}
			if strings.Contains(host, "_domainkey") {
				return []string{"v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAs81BQUzg/9fSZt8Org8vJlZYfHYe7fQhcKU6v0RB8KO+KSvHUS5+78j/Vkkn2RvNxw5oMaLxCNafXiRNOHux2oRKWRNtaXP/cSa5NbhCudFvOgooqATNqai/BRQbFCv6aCen11WPbjqyhgMCLuG1Ka3TP1kjvC4uB3FxnO4eSHWlc7QwY8oDj9ZWC3Ke2wrz1hCmQKZ9NPs9Ytdy72Ob2ZXENJ80XRk/BEKqxz9KonAbQAQfhULfEr+bLWCGFxaQREshNGKV/MjEhC+vzgzHFCfuCkAgHBs6fm60QCV3nYBXxelrHJ5fIyt74qG1WPshCf89e5saHuwh16sc7zxBkwIDAQAB"}, nil
			}
			return nil, nil
		}

		mockMXLookup := func(host string) ([]*net.MX, error) {
			return []*net.MX{{Host: "mail.example.com", Pref: 10}}, nil
		}

		mockHostLookup := func(host string) ([]string, error) {
			return []string{"127.0.0.1"}, nil
		}

		report := dns.RunDomainDoctor(context.Background(), dns.DoctorOptions{
			DomainName:     "example.com",
			MailHostname:   "mail.example.com",
			LookupTXTFunc:  mockTXTLookup,
			LookupMXFunc:   mockMXLookup,
			LookupHostFunc: mockHostLookup,
		})

		if !report.Healthy {
			for _, c := range report.Checks {
				if !c.Passed {
					t.Logf("Failed check: %s / %s -> %s", c.Category, c.Name, c.Message)
				}
			}
			t.Errorf("expected Domain Doctor report to be HEALTHY")
		}
	})
}
