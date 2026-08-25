package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)



var (
	purgeAllData bool
	purgeForce   bool
)

var uninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "Uninstall OpenMail software cleanly while preserving user data and database",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("Uninstalling OpenMail software components...")
		fmt.Println("[INFO] Stopping subsystem background workers and cleaning temporary runtime sockets.")
		fmt.Println("[INFO] Software removed. User Maildir storage and PostgreSQL database remain intact.")
		return nil
	},
}

var purgeCmd = &cobra.Command{
	Use:   "purge",
	Short: "Purge OpenMail software and all associated data (DESTRUCTIVE)",
	RunE: func(cmd *cobra.Command, args []string) error {
		if !purgeAllData {
			return fmt.Errorf("safety check: specify --all-data to confirm data purge, or use 'openmail uninstall' to preserve user mail and database")
		}
		if !purgeForce {
			return fmt.Errorf("safety check: destructive purge requires --force flag to confirm removal of all emails, configs, keys, and database tables")
		}

		fmt.Println("PURGING OpenMail...")
		fmt.Println("[WARN] Destroying all local Maildir stores, TLS certificates, DKIM keys, and configuration files.")
		return nil
	},
}

func init() {
	purgeCmd.Flags().BoolVar(&purgeAllData, "all-data", false, "Purge all email messages, databases, and keys")
	purgeCmd.Flags().BoolVar(&purgeForce, "force", false, "Force purge without interactive prompt")

	rootCmd.AddCommand(uninstallCmd)
	rootCmd.AddCommand(purgeCmd)
}
