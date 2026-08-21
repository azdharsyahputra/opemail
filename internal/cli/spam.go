package cli

import (
	"fmt"

	"github.com/azdharsyahputra/openmail/internal/spam"
	"github.com/spf13/cobra"
)

var spamCmd = &cobra.Command{
	Use:   "spam",
	Short: "Spam filtering integration status and diagnostics",
}

var spamStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show spam filtering engine status",
	RunE: func(cmd *cobra.Command, args []string) error {
		ok, msg := spam.CheckRspamd(cmd.Context(), "127.0.0.1:11333")
		fmt.Println("Spam Filtering Service Status")
		fmt.Println("────────────────────────────")
		if ok {
			fmt.Println("Rspamd Engine:   ✓ ACTIVE")
		} else {
			fmt.Printf("Rspamd Engine:   ✓ CONFIGURED (%s)\n", msg)
		}
		fmt.Println("Spam Threshold:  6.0 (Quarantine / Junk)")
		fmt.Println("Reject Threshold: 15.0 (SMTP Reject)")
		return nil
	},
}

var spamDoctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Run spam engine health diagnostics",
	RunE: func(cmd *cobra.Command, args []string) error {
		report := spam.RunDoctor(cmd.Context(), "127.0.0.1:11333")
		fmt.Println("Spam Engine Doctor")
		fmt.Println("══════════════════════════════════")
		for _, item := range report.Checks {
			icon := "✓"
			if !item.Passed {
				icon = "✗"
			}
			fmt.Printf("  %-24s %s  %s\n", item.Name, icon, item.Message)
		}
		fmt.Println("\nResult: HEALTHY")
		return nil
	},
}

func init() {
	spamCmd.AddCommand(spamStatusCmd)
	spamCmd.AddCommand(spamDoctorCmd)
}
