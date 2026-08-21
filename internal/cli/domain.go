package cli

import (
	"fmt"
	"net"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/azdharsyahputra/openmail/internal/config"
	"github.com/azdharsyahputra/openmail/internal/dns"
	"github.com/azdharsyahputra/openmail/internal/tls"
	"github.com/spf13/cobra"
)

var (
	spfPolicyFlag   string
	dmarcPolicyFlag string
)

var domainCmd = &cobra.Command{
	Use:   "domain",
	Short: "Manage email domains, SPF, DMARC, and domain diagnostics",
}

var domainCreateCmd = &cobra.Command{
	Use:   "create <domain>",
	Short: "Create a new domain",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		domainName := args[0]
		d, err := domainService.Create(cmd.Context(), domainName)
		if err != nil {
			return err
		}

		fmt.Println("Domain created successfully")
		fmt.Println()
		fmt.Printf("ID:     %s\n", d.ID)
		fmt.Printf("Domain: %s\n", d.Name)
		fmt.Printf("Status: %s\n", d.Status)
		return nil
	},
}

var domainListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all domains",
	RunE: func(cmd *cobra.Command, args []string) error {
		domains, err := domainService.List(cmd.Context())
		if err != nil {
			return err
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 4, ' ', 0)
		fmt.Fprintln(w, "DOMAIN\tSTATUS\tCREATED AT")
		for _, d := range domains {
			fmt.Fprintf(w, "%s\t%s\t%s\n", d.Name, d.Status, d.CreatedAt.Format("2006-01-02 15:04:05"))
		}
		w.Flush()
		return nil
	},
}

var domainDeleteCmd = &cobra.Command{
	Use:   "delete <domain>",
	Short: "Delete a domain",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		domainName := args[0]
		err := domainService.Delete(cmd.Context(), domainName)
		if err != nil {
			return err
		}

		fmt.Printf("Domain %s deleted successfully\n", domainName)
		return nil
	},
}

var domainSPFCmd = &cobra.Command{
	Use:   "spf",
	Short: "Manage and verify SPF policies",
}

var domainSPFShowCmd = &cobra.Command{
	Use:   "show <domain>",
	Short: "Show configured SPF policy for domain",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		domainName := args[0]
		pol, err := dkimService.GetPolicy(cmd.Context(), domainName)
		if err != nil {
			return err
		}

		fmt.Printf("SPF Policy for %s:\n", domainName)
		fmt.Printf("  Record: %s\n", pol.SPFPolicy)
		if err := dns.ValidateSPFSyntax(pol.SPFPolicy); err != nil {
			fmt.Printf("  Syntax: ✗ %v\n", err)
		} else {
			fmt.Println("  Syntax: ✓ Valid RFC 7208")
		}
		return nil
	},
}

var domainSPFSetCmd = &cobra.Command{
	Use:   "set <domain>",
	Short: "Set SPF policy for domain",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		domainName := args[0]
		if spfPolicyFlag == "" {
			return fmt.Errorf("--policy is required")
		}

		if err := dns.ValidateSPFSyntax(spfPolicyFlag); err != nil {
			return fmt.Errorf("invalid SPF policy syntax: %w", err)
		}

		if err := dkimService.SetSPFPolicy(cmd.Context(), domainName, spfPolicyFlag); err != nil {
			return err
		}

		fmt.Printf("SPF policy for %s updated successfully: %s\n", domainName, spfPolicyFlag)
		return nil
	},
}

var domainSPFVerifyCmd = &cobra.Command{
	Use:   "verify <domain>",
	Short: "Query and verify SPF record in DNS",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		domainName := args[0]

		records, err := net.LookupTXT(domainName)
		if err != nil || len(records) == 0 {
			fmt.Println("SPF Verification")
			fmt.Println("────────────────────────────")
			fmt.Printf("Domain: %s\n", domainName)
			fmt.Println("DNS:    ✗ TXT record not found")
			fmt.Println("Result: NOT READY")
			return nil
		}

		var spf string
		for _, r := range records {
			if strings.HasPrefix(strings.TrimSpace(r), "v=spf1") {
				spf = strings.TrimSpace(r)
				break
			}
		}

		fmt.Println("SPF Verification")
		fmt.Println("────────────────────────────")
		fmt.Printf("Domain: %s\n", domainName)
		if spf == "" {
			fmt.Println("DNS:    ✗ SPF record (v=spf1) not found")
			fmt.Println("Result: NOT READY")
			return nil
		}

		fmt.Printf("DNS:    ✓ Found: %s\n", spf)
		if err := dns.ValidateSPFSyntax(spf); err != nil {
			fmt.Printf("Syntax: ✗ %v\n", err)
			fmt.Println("Result: INVALID")
		} else {
			fmt.Println("Syntax: ✓ Valid RFC 7208")
			fmt.Println("Result: VERIFIED")
		}
		return nil
	},
}

var domainDMARCCmd = &cobra.Command{
	Use:   "dmarc",
	Short: "Manage and verify DMARC policies",
}

var domainDMARCShowCmd = &cobra.Command{
	Use:   "show <domain>",
	Short: "Show configured DMARC policy for domain",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		domainName := args[0]
		pol, err := dkimService.GetPolicy(cmd.Context(), domainName)
		if err != nil {
			return err
		}

		fmt.Printf("DMARC Policy for %s:\n", domainName)
		fmt.Printf("  Record: %s\n", pol.DMARCPolicy)
		if _, err := dns.ValidateDMARCSyntax(pol.DMARCPolicy); err != nil {
			fmt.Printf("  Syntax: ✗ %v\n", err)
		} else {
			fmt.Println("  Syntax: ✓ Valid RFC 7489")
		}
		return nil
	},
}

var domainDMARCSetCmd = &cobra.Command{
	Use:   "set <domain>",
	Short: "Set DMARC policy for domain",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		domainName := args[0]
		if dmarcPolicyFlag == "" {
			return fmt.Errorf("--policy is required")
		}

		if _, err := dns.ValidateDMARCSyntax(dmarcPolicyFlag); err != nil {
			return fmt.Errorf("invalid DMARC policy syntax: %w", err)
		}

		if err := dkimService.SetDMARCPolicy(cmd.Context(), domainName, dmarcPolicyFlag); err != nil {
			return err
		}

		fmt.Printf("DMARC policy for %s updated successfully: %s\n", domainName, dmarcPolicyFlag)
		return nil
	},
}

var domainDMARCVerifyCmd = &cobra.Command{
	Use:   "verify <domain>",
	Short: "Query and verify DMARC record in DNS",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		domainName := args[0]
		dmarcHost := "_dmarc." + domainName

		records, err := net.LookupTXT(dmarcHost)
		if err != nil || len(records) == 0 {
			fmt.Println("DMARC Verification")
			fmt.Println("────────────────────────────")
			fmt.Printf("Host:   %s\n", dmarcHost)
			fmt.Println("DNS:    ✗ TXT record not found")
			fmt.Println("Result: NOT READY")
			return nil
		}

		var dmarc string
		for _, r := range records {
			if strings.HasPrefix(strings.TrimSpace(r), "v=DMARC1") {
				dmarc = strings.TrimSpace(r)
				break
			}
		}

		fmt.Println("DMARC Verification")
		fmt.Println("────────────────────────────")
		fmt.Printf("Host:   %s\n", dmarcHost)
		if dmarc == "" {
			fmt.Println("DNS:    ✗ DMARC record (v=DMARC1) not found")
			fmt.Println("Result: NOT READY")
			return nil
		}

		fmt.Printf("DNS:    ✓ Found: %s\n", dmarc)
		if _, err := dns.ValidateDMARCSyntax(dmarc); err != nil {
			fmt.Printf("Syntax: ✗ %v\n", err)
			fmt.Println("Result: INVALID")
		} else {
			fmt.Println("Syntax: ✓ Valid RFC 7489")
			fmt.Println("Result: VERIFIED")
		}
		return nil
	},
}

var domainDoctorCmd = &cobra.Command{
	Use:   "doctor <domain>",
	Short: "Run comprehensive domain deliverability and security doctor",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		domainName := args[0]
		cfg, err := config.Load()
		if err != nil {
			return err
		}

		tlsProv := tls.NewFilesystemProvider(cfg.TLSBaseDir)

		report := dns.RunDomainDoctor(cmd.Context(), dns.DoctorOptions{
			DomainName:    domainName,
			MailHostname:  cfg.PostfixHostname,
			DomainService: domainService,
			DKIMService:   dkimService,
			TLSProvider:   tlsProv,
		})

		fmt.Println("Mail Domain Doctor")
		fmt.Println("══════════════════════════════════")
		fmt.Printf("Domain: %s\n\n", domainName)

		// Group checks by category
		categories := make(map[string][]dns.CheckItem)
		var catOrder []string
		for _, c := range report.Checks {
			if _, ok := categories[c.Category]; !ok {
				catOrder = append(catOrder, c.Category)
			}
			categories[c.Category] = append(categories[c.Category], c)
		}

		for _, cat := range catOrder {
			fmt.Println(cat)
			for _, item := range categories[cat] {
				icon := "✓"
				if !item.Passed {
					icon = "✗"
				}
				fmt.Printf("  %-28s %s  %s\n", item.Name, icon, item.Message)
			}
			fmt.Println()
		}

		if report.Healthy {
			fmt.Println("Result: HEALTHY")
		} else {
			fmt.Println("Result: UNHEALTHY / ATTENTION REQUIRED")
		}

		return nil
	},
}

func init() {
	domainSPFSetCmd.Flags().StringVar(&spfPolicyFlag, "policy", "", "SPF policy string (e.g. 'v=spf1 mx ~all')")
	domainDMARCSetCmd.Flags().StringVar(&dmarcPolicyFlag, "policy", "", "DMARC policy string (e.g. 'v=DMARC1; p=none')")

	domainSPFCmd.AddCommand(domainSPFShowCmd)
	domainSPFCmd.AddCommand(domainSPFSetCmd)
	domainSPFCmd.AddCommand(domainSPFVerifyCmd)

	domainDMARCCmd.AddCommand(domainDMARCShowCmd)
	domainDMARCCmd.AddCommand(domainDMARCSetCmd)
	domainDMARCCmd.AddCommand(domainDMARCVerifyCmd)

	domainCmd.AddCommand(domainCreateCmd)
	domainCmd.AddCommand(domainListCmd)
	domainCmd.AddCommand(domainDeleteCmd)
	domainCmd.AddCommand(domainSPFCmd)
	domainCmd.AddCommand(domainDMARCCmd)
	domainCmd.AddCommand(domainDoctorCmd)
}
