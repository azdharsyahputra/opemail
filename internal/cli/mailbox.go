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
			// If not specified via flag, default to a secure default or prompt
			password = "Password123!"
			fmt.Println("Note: No password provided via --password, using default test password 'Password123!'")
		}

		m, err := mailboxService.Create(cmd.Context(), email, password, mailboxQuota)
		if err != nil {
			return err
		}

		fmt.Println("Mailbox created successfully")
		fmt.Println()
		fmt.Printf("ID:        %s\n", m.ID)
		fmt.Printf("Email:     %s\n", m.Email)
		fmt.Printf("Domain:    %s\n", m.DomainName)
		fmt.Printf("Quota:     %d bytes\n", m.QuotaBytes)
		fmt.Printf("Status:    %s\n", m.Status)
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
		fmt.Fprintln(w, "EMAIL\tDOMAIN\tSTATUS")
		for _, m := range mailboxes {
			fmt.Fprintf(w, "%s\t%s\t%s\n", m.Email, m.DomainName, m.Status)
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

func init() {
	mailboxCreateCmd.Flags().StringVarP(&mailboxPassword, "password", "p", "", "Password for the mailbox (min 8 chars)")
	mailboxCreateCmd.Flags().Int64VarP(&mailboxQuota, "quota", "q", 1073741824, "Quota in bytes (default 1GB)")

	mailboxCmd.AddCommand(mailboxCreateCmd)
	mailboxCmd.AddCommand(mailboxListCmd)
	mailboxCmd.AddCommand(mailboxDeleteCmd)
}
