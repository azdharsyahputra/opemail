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

		passStdin, _ := cmd.Flags().GetBool("password-stdin")
		password := mailboxPassword
		if passStdin {
			var input string
			_, err := fmt.Fscanln(os.Stdin, &input)
			if err != nil && input == "" {
				return fmt.Errorf("failed to read password from stdin: %w", err)
			}
			password = input
		} else if password == "" {
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
			fmt.Printf("Mailbox %s already provisioned.\n", email)
		} else {
			fmt.Printf("Mailbox %s successfully provisioned.\n", email)
		}
		return nil
	},
}

var mailboxDoctorCmd = &cobra.Command{
	Use:   "doctor <email>",
	Short: "Inspect Maildir directory and permissions for a mailbox",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		email := args[0]
		report, err := mailboxService.Doctor(cmd.Context(), email)
		if err != nil {

			return err
		}

		fmt.Printf("Mailbox Doctor Report for %s\n", report.Email)
		fmt.Println("========================================")
		fmt.Printf("Database Status:      %s\n", report.Status)
		fmt.Printf("Provisioning Status:  %s\n", report.ProvisionStatus)
		fmt.Printf("Root Path:            %s\n\n", report.Root)

		fmt.Printf("[%s] Maildir Directory:  %s\n", checkMark(report.MaildirExists.Passed), report.MaildirExists.Message)
		fmt.Printf("[%s] Cur Subdirectory:   %s\n", checkMark(report.CurExists.Passed), report.CurExists.Message)
		fmt.Printf("[%s] New Subdirectory:   %s\n", checkMark(report.NewExists.Passed), report.NewExists.Message)
		fmt.Printf("[%s] Tmp Subdirectory:   %s\n", checkMark(report.TmpExists.Passed), report.TmpExists.Message)
		fmt.Printf("[%s] Directory Ownership:%s\n", checkMark(report.Ownership.Passed), report.Ownership.Message)
		fmt.Printf("[%s] Directory Mode:     %s\n\n", checkMark(report.Permission.Passed), report.Permission.Message)

		if report.Healthy {
			fmt.Println("Result: HEALTHY")
		} else {
			fmt.Println("Result: UNHEALTHY / ISSUES DETECTED")
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

var mailboxPasswordCmd = &cobra.Command{
	Use:   "password",
	Short: "Manage mailbox passwords",
}

var mailboxPasswordSetCmd = &cobra.Command{
	Use:   "set <email>",
	Short: "Update mailbox password",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		email := args[0]
		passStdin, _ := cmd.Flags().GetBool("password-stdin")
		password := mailboxPassword
		if passStdin {
			var input string
			_, err := fmt.Fscanln(os.Stdin, &input)
			if err != nil && input == "" {
				return fmt.Errorf("failed to read password from stdin: %w", err)
			}
			password = input
		} else if password == "" {
			return fmt.Errorf("please provide password via --password or --password-stdin")
		}

		err := mailboxService.SetPassword(cmd.Context(), email, password)
		if err != nil {
			return err
		}

		fmt.Printf("Password for %s updated successfully\n", email)
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
	mailboxCreateCmd.Flags().Bool("password-stdin", false, "Read password from standard input (prevents exposure in process table)")
	mailboxCreateCmd.Flags().Int64VarP(&mailboxQuota, "quota", "q", 1073741824, "Quota in bytes (default 1GB)")

	mailboxPasswordSetCmd.Flags().StringVarP(&mailboxPassword, "password", "p", "", "New password for the mailbox (min 8 chars)")
	mailboxPasswordSetCmd.Flags().Bool("password-stdin", false, "Read password from standard input (prevents exposure in process table)")

	mailboxPasswordCmd.AddCommand(mailboxPasswordSetCmd)

	mailboxCmd.AddCommand(mailboxCreateCmd)
	mailboxCmd.AddCommand(mailboxProvisionCmd)
	mailboxCmd.AddCommand(mailboxDoctorCmd)
	mailboxCmd.AddCommand(mailboxListCmd)
	mailboxCmd.AddCommand(mailboxDeleteCmd)
	mailboxCmd.AddCommand(mailboxPasswordCmd)
}
