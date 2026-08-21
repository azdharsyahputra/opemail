package cli

import (
	"fmt"

	"github.com/azdharsyahputra/openmail/internal/abuse"
	"github.com/spf13/cobra"
)

var (
	abuseMsgsPerMin  int
	abuseMsgsPerHour int
	abuseRcptPerDay  int
	abuseEnabled     bool
)

var abuseCmd = &cobra.Command{
	Use:   "abuse",
	Short: "Outbound submission rate limits and abuse protection controls",
}

var abuseStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show outbound submission abuse and rate limiting status",
	RunE: func(cmd *cobra.Command, args []string) error {
		report := abuse.RunDoctor(cmd.Context(), db)
		fmt.Println("Abuse & Rate Limiting Status")
		fmt.Println("────────────────────────────")
		for _, item := range report.Checks {
			icon := "✓"
			if !item.Passed {
				icon = "✗"
			}
			fmt.Printf("  %-24s %s  %s\n", item.Name, icon, item.Message)
		}
		return nil
	},
}

var abuseLimitsCmd = &cobra.Command{
	Use:   "limits",
	Short: "Manage mailbox submission rate limits",
}

var abuseLimitsShowCmd = &cobra.Command{
	Use:   "show <email>",
	Short: "Show submission rate limits for a mailbox",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		email := args[0]
		limits, err := abuseService.GetLimits(cmd.Context(), email)
		if err != nil {
			return err
		}

		fmt.Printf("Submission Rate Limits for %s:\n", email)
		fmt.Printf("  Messages / Minute: %d\n", limits.MessagesPerMinute)
		fmt.Printf("  Messages / Hour:   %d\n", limits.MessagesPerHour)
		fmt.Printf("  Recipients / Day:  %d\n", limits.RecipientsPerDay)
		fmt.Printf("  Limiting Enabled:  %t\n", limits.Enabled)
		return nil
	},
}

var abuseLimitsSetCmd = &cobra.Command{
	Use:   "set <email>",
	Short: "Set submission rate limits for a mailbox",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		email := args[0]

		limits := &abuse.MailboxLimits{
			MessagesPerMinute: abuseMsgsPerMin,
			MessagesPerHour:   abuseMsgsPerHour,
			RecipientsPerDay:  abuseRcptPerDay,
			Enabled:           abuseEnabled,
		}

		if err := abuseService.SetLimits(cmd.Context(), email, limits); err != nil {
			return err
		}

		fmt.Printf("Rate limits for %s updated successfully\n", email)
		return nil
	},
}

func init() {
	abuseLimitsSetCmd.Flags().IntVar(&abuseMsgsPerMin, "msgs-per-min", 30, "Max messages per minute")
	abuseLimitsSetCmd.Flags().IntVar(&abuseMsgsPerHour, "msgs-per-hour", 300, "Max messages per hour")
	abuseLimitsSetCmd.Flags().IntVar(&abuseRcptPerDay, "rcpt-per-day", 1000, "Max recipients per day")
	abuseLimitsSetCmd.Flags().BoolVar(&abuseEnabled, "enabled", true, "Enable rate limiting")

	abuseLimitsCmd.AddCommand(abuseLimitsShowCmd)
	abuseLimitsCmd.AddCommand(abuseLimitsSetCmd)

	abuseCmd.AddCommand(abuseStatusCmd)
	abuseCmd.AddCommand(abuseLimitsCmd)
}
