package cli

import (
	"fmt"

	"github.com/azdharsyahputra/openmail/internal/config"
	"github.com/azdharsyahputra/openmail/internal/identity"
	"github.com/spf13/cobra"
)

var ldapCmd = &cobra.Command{
	Use:   "ldap",
	Short: "Inspect and manage LDAP directory integration",
}

var ldapDoctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Run comprehensive diagnostics on LDAP directory connection, TLS, and schema",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load()
		if err != nil {
			return err
		}

		svc, err := initIdentityService(cfg)
		if err != nil {
			return err
		}

		report, err := svc.Doctor(cmd.Context())
		if err != nil {
			return err
		}

		fmt.Println("========================================")
		fmt.Println("         MailOpen LDAP Doctor           ")
		fmt.Println("========================================")
		fmt.Printf("Provider:                  %s\n", report.ProviderName)
		fmt.Printf("Configuration:             %s\n", formatCheck(report.ConfigOK))
		fmt.Printf("TLS & Certificate:         %s\n", formatCheck(report.TLSOK))
		fmt.Printf("Connection & Service Bind: %s\n", formatCheck(report.ConnectionOK))
		fmt.Printf("Directory Search:          %s\n", formatCheck(report.SearchOK))
		fmt.Println("----------------------------------------")
		if report.Healthy {
			fmt.Println("Result: HEALTHY")
		} else {
			fmt.Println("Result: UNHEALTHY")
			for _, e := range report.Errors {
				fmt.Printf(" - Error: %s\n", e)
			}
		}
		return nil
	},
}

func formatCheck(ok bool) string {
	if ok {
		return "✓ OK"
	}
	return "✗ FAILED"
}

var ldapSyncCmd = &cobra.Command{
	Use:   "sync",
	Short: "Synchronize LDAP users into MailOpen virtual mailboxes",
	RunE: func(cmd *cobra.Command, args []string) error {
		domName, _ := cmd.Flags().GetString("domain")
		autoCreate, _ := cmd.Flags().GetBool("auto-create")
		dryRun, _ := cmd.Flags().GetBool("dry-run")

		cfg, err := config.Load()
		if err != nil {
			return err
		}

		svc, err := initIdentityService(cfg)
		if err != nil {
			return err
		}

		report, err := svc.Sync(cmd.Context(), identity.SyncOptions{
			DomainName:        domName,
			AutoCreateMailbox: autoCreate,
			DryRun:            dryRun,
		})
		if err != nil {
			return err
		}

		fmt.Printf("LDAP Sync Complete (%v)\n", report.Duration)
		fmt.Printf("Total Identities: %d\n", report.TotalIdentities)
		fmt.Printf("Created:          %d\n", report.Created)
		fmt.Printf("Updated:          %d\n", report.Updated)
		fmt.Printf("Suspended:        %d\n", report.Suspended)
		fmt.Printf("Skipped:          %d\n", report.Skipped)
		return nil
	},
}

func init() {
	ldapCmd.AddCommand(ldapDoctorCmd)
	ldapSyncCmd.Flags().String("domain", "", "Filter synchronization to specific domain")
	ldapSyncCmd.Flags().Bool("auto-create", false, "Automatically provision new mailboxes for discovered identities")
	ldapSyncCmd.Flags().Bool("dry-run", false, "Simulate sync without modifying database")
	ldapCmd.AddCommand(ldapSyncCmd)

	rootCmd.AddCommand(ldapCmd)
}
