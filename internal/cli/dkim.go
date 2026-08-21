package cli

import (
	"fmt"
	"os"

	"github.com/azdharsyahputra/openmail/internal/config"
	"github.com/azdharsyahputra/openmail/internal/dkim"
	"github.com/spf13/cobra"
)

var (
	dkimSelectorFlag string
)

var dkimCmd = &cobra.Command{
	Use:   "dkim",
	Short: "Manage DKIM cryptographic keys, selectors, and DNS verification",
}

var dkimKeyCmd = &cobra.Command{
	Use:   "key",
	Short: "DKIM key management operations",
}

var dkimKeyGenerateCmd = &cobra.Command{
	Use:   "generate <domain>",
	Short: "Generate a new RSA-2048 DKIM key and prepare DNS record",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		domainName := args[0]
		selector := dkimSelectorFlag
		if selector == "" {
			selector = "mailopen2026"
		}

		key, pair, err := dkimService.GenerateKey(cmd.Context(), domainName, selector)
		if err != nil {
			return err
		}

		dnsName := dkim.BuildDNSName(domainName, selector)
		cfg, _ := config.Load()
		privKeyPath := fmt.Sprintf("%s/%s/%s/private.key", cfg.DKIMBaseDir, domainName, selector)

		fmt.Println("DKIM key generated successfully")
		fmt.Println()
		fmt.Println("Domain:")
		fmt.Printf("  %s\n\n", domainName)
		fmt.Println("Selector:")
		fmt.Printf("  %s\n\n", selector)
		fmt.Println("Algorithm:")
		fmt.Printf("  %s\n\n", key.Algorithm)
		fmt.Println("Key Size:")
		fmt.Printf("  %d\n\n", key.KeyBits)
		fmt.Println("Status:")
		fmt.Printf("  %s\n\n", key.Status)
		fmt.Println("DNS Record Name:")
		fmt.Printf("  %s TXT\n\n", dnsName)
		fmt.Println("DNS Record Value:")
		fmt.Printf("  %s\n\n", dkim.BuildDNSTXTValue(pair.PublicKeyDNS))
		fmt.Println("Private Key:")
		fmt.Printf("  %s\n", privKeyPath)

		return nil
	},
}

var dkimKeyListCmd = &cobra.Command{
	Use:   "list <domain>",
	Short: "List all DKIM keys and statuses for a domain",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		domainName := args[0]

		keys, err := dkimService.ListKeys(cmd.Context(), domainName)
		if err != nil {
			return err
		}

		if len(keys) == 0 {
			fmt.Printf("No DKIM keys found for domain %s\n", domainName)
			return nil
		}

		fmt.Printf("DKIM Keys for %s:\n", domainName)
		fmt.Println("─────────────────────────────────────────────────────────────────────────────")
		fmt.Printf("%-18s %-12s %-10s %-10s %-20s\n", "SELECTOR", "ALGORITHM", "BITS", "STATUS", "CREATED AT")
		fmt.Println("─────────────────────────────────────────────────────────────────────────────")
		for _, k := range keys {
			fmt.Printf("%-18s %-12s %-10d %-10s %-20s\n",
				k.Selector,
				k.Algorithm,
				k.KeyBits,
				k.Status,
				k.CreatedAt.Format("2006-01-02 15:04:05"),
			)
		}
		return nil
	},
}

var dkimKeyActivateCmd = &cobra.Command{
	Use:   "activate <domain> <selector>",
	Short: "Activate a verified DKIM key for live email signing",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		domainName := args[0]
		selector := args[1]

		if err := dkimService.ActivateKey(cmd.Context(), domainName, selector); err != nil {
			return err
		}

		fmt.Printf("DKIM key for %s (selector: %s) activated successfully\n", domainName, selector)
		return nil
	},
}

var dkimKeyRevokeCmd = &cobra.Command{
	Use:   "revoke <domain> <selector>",
	Short: "Revoke a DKIM key selector",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		domainName := args[0]
		selector := args[1]

		if err := dkimService.RevokeKey(cmd.Context(), domainName, selector); err != nil {
			return err
		}

		fmt.Printf("DKIM key for %s (selector: %s) revoked successfully\n", domainName, selector)
		return nil
	},
}

var dkimVerifyCmd = &cobra.Command{
	Use:   "verify <domain>",
	Short: "Verify DKIM DNS record publication and local private key match",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		domainName := args[0]
		selector := dkimSelectorFlag
		if selector == "" {
			activeKey, err := dkimService.GetActiveKey(cmd.Context(), domainName)
			if err == nil && activeKey != nil {
				selector = activeKey.Selector
			} else {
				selector = "mailopen2026"
			}
		}

		res, err := dkimService.VerifyDNS(cmd.Context(), domainName, selector, nil)

		fmt.Println("DKIM Verification")
		fmt.Println("────────────────────────────")
		fmt.Println("Domain:")
		fmt.Printf("  %s\n\n", domainName)
		fmt.Println("Selector:")
		fmt.Printf("  %s\n\n", selector)

		if res == nil || !res.DNSRecordFound {
			fmt.Println("DNS:")
			fmt.Println("  ✗ TXT record not found")
			fmt.Println()
			fmt.Println("Result:")
			fmt.Println("  NOT READY")
			return nil
		}

		dnsIcon := "✓"
		keyIcon := "✓"
		matchIcon := "✓"
		if !res.PublicKeyValid {
			keyIcon = "✗"
		}
		if !res.KeyMatches {
			matchIcon = "✗"
		}

		fmt.Println("DNS:")
		fmt.Printf("  %s TXT record found\n\n", dnsIcon)
		fmt.Println("Key:")
		fmt.Printf("  %s RSA public key valid\n\n", keyIcon)
		fmt.Println("Fingerprint:")
		fmt.Printf("  %s matches local key\n\n", matchIcon)
		fmt.Println("Result:")
		fmt.Printf("  %s\n", res.Status)

		if err != nil {
			os.Exit(1)
		}
		return nil
	},
}

var dkimDoctorCmd = &cobra.Command{
	Use:   "doctor <domain>",
	Short: "Run comprehensive DKIM diagnostic checks",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		domainName := args[0]

		report := dkim.RunDKIMDoctor(cmd.Context(), dkimService, domainName, nil)

		fmt.Println("MailOpen DKIM Doctor")
		fmt.Println("══════════════════════════════════")
		fmt.Printf("Target Domain: %s\n\n", domainName)

		for _, item := range report.Checks {
			icon := "✓"
			if !item.Passed {
				icon = "✗"
			}
			fmt.Printf("  [%s] %-24s %s  %s\n", item.Category, item.Name, icon, item.Message)
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

func init() {
	dkimKeyGenerateCmd.Flags().StringVar(&dkimSelectorFlag, "selector", "mailopen2026", "DKIM selector name")
	dkimVerifyCmd.Flags().StringVar(&dkimSelectorFlag, "selector", "", "DKIM selector name to verify (defaults to active key)")

	dkimKeyCmd.AddCommand(dkimKeyGenerateCmd)
	dkimKeyCmd.AddCommand(dkimKeyListCmd)
	dkimKeyCmd.AddCommand(dkimKeyActivateCmd)
	dkimKeyCmd.AddCommand(dkimKeyRevokeCmd)

	dkimCmd.AddCommand(dkimKeyCmd)
	dkimCmd.AddCommand(dkimVerifyCmd)
	dkimCmd.AddCommand(dkimDoctorCmd)
}
