package cli

import (
	"fmt"
	"net"

	"github.com/azdharsyahputra/openmail/internal/config"
	"github.com/azdharsyahputra/openmail/internal/inbound"
	"github.com/spf13/cobra"
)

var inboundCmd = &cobra.Command{
	Use:   "inbound",
	Short: "Manage inbound mail security, policy evaluation, and diagnostics",
}

var inboundDoctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Run comprehensive inbound security and MTA diagnostics",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load()
		if err != nil {
			return err
		}

		report := inbound.RunInboundDoctor(cmd.Context(), db, cfg.PostfixConfigDir)

		fmt.Println("OpenMail Inbound Security Doctor")
		fmt.Println("══════════════════════════════════")

		for _, item := range report.Checks {
			icon := "✓"
			if !item.Passed {
				icon = "✗"
			}
			fmt.Printf("  [%-20s] %-22s %s  %s\n", item.Category, item.Name, icon, item.Message)
		}
		fmt.Println()

		if report.Healthy {
			fmt.Println("Result: HEALTHY")
		} else {
			fmt.Println("Result: UNHEALTHY / ATTENTION REQUIRED")
		}

		return nil
	},
}

var inboundTestCmd = &cobra.Command{
	Use:   "test",
	Short: "Run inbound policy and authentication simulation tests",
}

var inboundTestSMTPCmd = &cobra.Command{
	Use:   "smtp",
	Short: "Test inbound SMTP connection controls and banner",
	RunE: func(cmd *cobra.Command, args []string) error {
		conn, err := net.Dial("tcp", "127.0.0.1:25")
		if err != nil {
			fmt.Printf("Inbound SMTP :25 connect FAILED: %v\n", err)
			return err
		}
		defer conn.Close()

		buf := make([]byte, 1024)
		n, _ := conn.Read(buf)
		fmt.Printf("Inbound SMTP :25 Banner: %s", string(buf[:n]))
		fmt.Println("Status: OK")
		return nil
	},
}

var inboundTestSPFCmd = &cobra.Command{
	Use:   "spf <ip> <domain> <spf_record>",
	Short: "Simulate SPF evaluation for a client IP and sender SPF record",
	Args:  cobra.ExactArgs(3),
	RunE: func(cmd *cobra.Command, args []string) error {
		ip := net.ParseIP(args[0])
		if ip == nil {
			return fmt.Errorf("invalid IP address: %s", args[0])
		}
		domain := args[1]
		spfRecord := args[2]

		status := inbound.EvaluateSPF(ip, domain, spfRecord)
		fmt.Println("SPF Evaluation Result")
		fmt.Println("────────────────────────────")
		fmt.Printf("Client IP:    %s\n", ip.String())
		fmt.Printf("Domain:       %s\n", domain)
		fmt.Printf("SPF Record:   %s\n", spfRecord)
		fmt.Printf("Result:       %s\n", status)
		return nil
	},
}

var inboundTestDKIMCmd = &cobra.Command{
	Use:   "dkim <domain> <selector>",
	Short: "Test DKIM inbound verification against public DNS key",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		domain := args[0]
		selector := args[1]

		res, err := dkimService.VerifyDNS(cmd.Context(), domain, selector, nil)
		if err != nil && (res == nil || !res.DNSRecordFound) {
			fmt.Printf("DKIM verification FAILED: %v\n", err)
			return nil
		}

		fmt.Println("DKIM Verification Result")
		fmt.Println("────────────────────────────")
		fmt.Printf("Domain:       %s\n", domain)
		fmt.Printf("Selector:     %s\n", selector)
		fmt.Printf("DNS Record:   %t\n", res.DNSRecordFound)
		fmt.Printf("Public Key:   %t\n", res.PublicKeyValid)
		fmt.Printf("Key Match:    %t\n", res.KeyMatches)
		fmt.Printf("Verdict:      %s\n", res.Status)
		return nil
	},
}

var inboundTestDMARCCmd = &cobra.Command{
	Use:   "dmarc <header_from> <spf_status> <spf_domain> <dkim_status> <dkim_domain> <dmarc_policy>",
	Short: "Simulate DMARC alignment and policy enforcement verdict",
	Args:  cobra.ExactArgs(6),
	RunE: func(cmd *cobra.Command, args []string) error {
		headerFrom := args[0]
		spfStatus := inbound.AuthStatus(args[1])
		spfDomain := args[2]
		dkimStatus := inbound.AuthStatus(args[3])
		dkimDomain := args[4]
		dmarcPolicy := args[5]

		spf := inbound.SPFVerification{Status: spfStatus, Domain: spfDomain}
		dkim := inbound.DKIMVerification{Status: dkimStatus, Domain: dkimDomain}

		res := inbound.EvaluateDMARC(headerFrom, spf, dkim, dmarcPolicy)

		fmt.Println("DMARC Evaluation Result")
		fmt.Println("────────────────────────────")
		fmt.Printf("Header From:  %s\n", headerFrom)
		fmt.Printf("SPF:          %s (domain: %s, aligned: %t)\n", spfStatus, spfDomain, res.SPFAligned)
		fmt.Printf("DKIM:         %s (domain: %s, aligned: %t)\n", dkimStatus, dkimDomain, res.DKIMAligned)
		fmt.Printf("Policy:       %s\n", dmarcPolicy)
		fmt.Printf("DMARC Status: %s\n", res.Status)
		fmt.Printf("Final Action: %s (%s)\n", res.Action, res.Reason)
		return nil
	},
}

func init() {
	inboundTestCmd.AddCommand(inboundTestSMTPCmd)
	inboundTestCmd.AddCommand(inboundTestSPFCmd)
	inboundTestCmd.AddCommand(inboundTestDKIMCmd)
	inboundTestCmd.AddCommand(inboundTestDMARCCmd)

	inboundCmd.AddCommand(inboundDoctorCmd)
	inboundCmd.AddCommand(inboundTestCmd)
}
