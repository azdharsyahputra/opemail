package cli

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"
)

var (
	mailboxPassword string
	mailboxQuota    int64
)

var mailboxCmd = &cobra.Command{
	Use:   "mailbox",
	Short: "Manage mailboxes",
}

var mailboxCreateCmd = &cobra.Command{
	Use:   "create <email>",
	Short: "Create a new mailbox",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		email := args[0]

		password := mailboxPassword
		if password == "" {
			// If not specified via flag, default to a secure default
			password = "Password123!"
			fmt.Println("Note: No password provided via --password, using default test password 'Password123!'")
		}

		m, err := mailboxService.Create(cmd.Context(), email, password, mailboxQuota)
		if err != nil {
			return err
		}

		fmt.Println("Mailbox created successfully")
		fmt.Println()
		fmt.Printf("ID:         %s\n", m.ID)
		fmt.Printf("Email:      %s\n", m.Email)
		fmt.Printf("Domain:     %s\n", m.DomainName)
		fmt.Printf("Quota:      %d bytes\n", m.QuotaBytes)
		fmt.Printf("Status:     %s\n", m.Status)
		fmt.Printf("Provision:  %s\n", m.ProvisioningStatus)
		return nil
	},
}

var mailboxProvisionCmd = &cobra.Command{
	Use:   "provision <email>",
	Short: "Provision or retry provisioning for a mailbox",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		email := args[0]
		_, alreadyProvisioned, err := mailboxService.Provision(cmd.Context(), email)
		if err != nil {
			return err
		}

		if alreadyProvisioned {
			fmt.Println("Mailbox already provisioned")
		} else {
			fmt.Printf("Mailbox %s provisioned successfully\n", email)
		}
		return nil
	},
}

var mailboxDoctorCmd = &cobra.Command{
	Use:   "doctor <email>",
	Short: "Inspect health and filesystem provisioning of a mailbox",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		email := args[0]
		report, err := mailboxService.Doctor(cmd.Context(), email)
		if err != nil {
			return err
		}

		fmt.Println("Mailbox Doctor")
		fmt.Println("──────────────────────────────")
		fmt.Println()
		fmt.Println("Mailbox")
		fmt.Printf("  Email       %s\n", report.Email)
		fmt.Printf("  Status      %s\n", report.Status)
		fmt.Printf("  Provision   %s\n", report.ProvisionStatus)
		fmt.Println()
		fmt.Println("Filesystem")
		fmt.Printf("  Root        %s\n", report.Root)
		fmt.Printf("  Maildir     %s\n", checkMark(report.MaildirExists.Passed))
		fmt.Printf("  cur         %s\n", checkMark(report.CurExists.Passed))
		fmt.Printf("  new         %s\n", checkMark(report.NewExists.Passed))
		fmt.Printf("  tmp         %s\n", checkMark(report.TmpExists.Passed))
		fmt.Printf("  Owner       %s %s\n", report.Ownership.Message, checkMark(report.Ownership.Passed))
		fmt.Printf("  Permission  %s %s\n", report.Permission.Message, checkMark(report.Permission.Passed))
		fmt.Println()

		if report.Healthy {
			fmt.Println("Result: HEALTHY")
		} else {
			fmt.Println("Result: UNHEALTHY / DEGRADED")
		}

		return nil
	},
}

var mailboxListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all mailboxes",
	RunE: func(cmd *cobra.Command, args []string) error {
		mailboxes, err := mailboxService.List(cmd.Context())
		if err != nil {
			return err
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 4, ' ', 0)
		fmt.Fprintln(w, "EMAIL\tDOMAIN\tSTATUS\tPROVISION")
		for _, m := range mailboxes {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", m.Email, m.DomainName, m.Status, m.ProvisioningStatus)
		}
		w.Flush()
		return nil
	},
}

var mailboxDeleteCmd = &cobra.Command{
	Use:   "delete <email>",
	Short: "Delete a mailbox",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		email := args[0]
		err := mailboxService.Delete(cmd.Context(), email)
		if err != nil {
			return err
		}

		fmt.Printf("Mailbox %s deleted successfully\n", email)
		return nil
	},
}

func checkMark(passed bool) string {
	if passed {
		return "✓"
	}
	return "✗"
}

func init() {
	mailboxCreateCmd.Flags().StringVarP(&mailboxPassword, "password", "p", "", "Password for the mailbox (min 8 chars)")
	mailboxCreateCmd.Flags().Int64VarP(&mailboxQuota, "quota", "q", 1073741824, "Quota in bytes (default 1GB)")

	mailboxCmd.AddCommand(mailboxCreateCmd)
	mailboxCmd.AddCommand(mailboxProvisionCmd)
	mailboxCmd.AddCommand(mailboxDoctorCmd)
	mailboxCmd.AddCommand(mailboxListCmd)
	mailboxCmd.AddCommand(mailboxDeleteCmd)
}
