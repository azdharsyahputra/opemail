package cli

import (
	"fmt"
	"os"

	"github.com/azdharsyahputra/openmail/internal/bounce"
	"github.com/spf13/cobra"
)

var bounceCmd = &cobra.Command{
	Use:   "bounce",
	Short: "Classify and parse SMTP bounce replies and DSN reports",
}

var bounceClassifyCmd = &cobra.Command{
	Use:   "classify <text-or-smtp-reply>",
	Short: "Classify bounce reason, enhanced status code, and permanent vs temporary type",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		report := bounce.ClassifyBounce(args[0])

		fmt.Println("\nBounce Classification")
		fmt.Println("────────────────────────────")
		fmt.Printf("Type:           %s\n", report.Type)
		fmt.Printf("Category:       %s\n", report.Category)
		fmt.Printf("Enhanced Code:  %s\n", report.EnhancedCode)
		fmt.Printf("Reply Code:     %d\n", report.ReplyCode)
		fmt.Printf("Hard Bounce:    %t\n", report.IsHardBounce)
		fmt.Printf("Diagnostic:     %s\n", report.DiagnosticCode)
		return nil
	},
}

var bounceParseCmd = &cobra.Command{
	Use:   "parse <dsn-file>",
	Short: "Parse an RFC 3464 DSN (Delivery Status Notification) MIME message",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		content, err := os.ReadFile(args[0])
		if err != nil {
			return fmt.Errorf("read dsn file: %w", err)
		}

		report := bounce.ParseDSN(string(content))

		fmt.Println("\nDSN Bounce Report")
		fmt.Println("────────────────────────────")
		fmt.Printf("Original Recipient: %s\n", report.OriginalRecipient)
		fmt.Printf("Remote MTA:         %s\n", report.RemoteMTA)
		fmt.Printf("Type:               %s\n", report.Type)
		fmt.Printf("Category:           %s\n", report.Category)
		fmt.Printf("Enhanced Code:      %s\n", report.EnhancedCode)
		fmt.Printf("Reply Code:         %d\n", report.ReplyCode)
		fmt.Printf("Hard Bounce:        %t\n", report.IsHardBounce)
		return nil
	},
}

func init() {
	bounceCmd.AddCommand(bounceClassifyCmd)
	bounceCmd.AddCommand(bounceParseCmd)
}
