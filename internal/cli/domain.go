package cli

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"
)

var domainCmd = &cobra.Command{
	Use:   "domain",
	Short: "Manage email domains",
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

func init() {
	domainCmd.AddCommand(domainCreateCmd)
	domainCmd.AddCommand(domainListCmd)
	domainCmd.AddCommand(domainDeleteCmd)
}
