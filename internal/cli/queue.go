package cli

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/azdharsyahputra/openmail/internal/queue"
	"github.com/spf13/cobra"
)

var queueCmd = &cobra.Command{
	Use:   "queue",
	Short: "Manage and inspect Postfix mail queues",
}

var queueStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Display summary counts of Postfix mail queue",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		driver := queue.NewSystemDriver("mailopen_postfix")
		svc := queue.NewService(driver)

		summary, err := svc.GetStatus(ctx)
		if err != nil {
			return fmt.Errorf("failed to get queue status: %w", err)
		}

		fmt.Println("\nMail Queue")
		fmt.Println("────────────────────────────")
		fmt.Printf("Active       %d\n", summary.Active)
		fmt.Printf("Deferred     %d\n", summary.Deferred)
		fmt.Printf("Hold         %d\n", summary.Hold)
		fmt.Printf("Bounce       %d\n", summary.Bounce)
		fmt.Printf("Total        %d\n\n", summary.Total)

		if summary.OldestMessage != nil {
			fmt.Println("Oldest")
			fmt.Printf("  Queue ID    %s\n", summary.OldestMessage.QueueID)
			fmt.Printf("  Age         %s\n", summary.OldestMessage.Age)
			fmt.Printf("  Recipient   %s\n", summary.OldestMessage.Recipient)
			fmt.Printf("  Status      %s\n", summary.OldestMessage.Status)
		}
		return nil
	},
}

var queueListCmd = &cobra.Command{
	Use:   "list",
	Short: "List queued messages with optional status filter",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		driver := queue.NewSystemDriver("mailopen_postfix")
		svc := queue.NewService(driver)

		filterStatus, _ := cmd.Flags().GetString("status")
		messages, err := svc.List(ctx, filterStatus)
		if err != nil {
			return fmt.Errorf("failed to list queue: %w", err)
		}

		if len(messages) == 0 {
			fmt.Println("Mail queue is empty.")
			return nil
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
		fmt.Fprintln(w, "QUEUE ID\tRECIPIENT\tAGE\tSTATUS\tREASON")
		for _, m := range messages {
			reason := m.Reason
			if len(reason) > 40 {
				reason = reason[:37] + "..."
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", m.QueueID, m.Recipient, m.Age, m.Status, reason)
		}
		return w.Flush()
	},
}

var queueInspectCmd = &cobra.Command{
	Use:   "inspect <queue-id>",
	Short: "Inspect the raw headers and content of a queued message (postcat)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		driver := queue.NewSystemDriver("mailopen_postfix")
		svc := queue.NewService(driver)

		content, err := svc.Inspect(ctx, args[0])
		if err != nil {
			return fmt.Errorf("failed to inspect message %s: %w", args[0], err)
		}

		fmt.Println(content)
		return nil
	},
}

var queueRetryCmd = &cobra.Command{
	Use:   "retry <queue-id>",
	Short: "Requeue a deferred message for immediate retry attempt (postsuper -r)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		driver := queue.NewSystemDriver("mailopen_postfix")
		svc := queue.NewService(driver)

		if err := svc.Retry(ctx, args[0]); err != nil {
			return fmt.Errorf("failed to retry queue %s: %w", args[0], err)
		}

		fmt.Printf("Message %s requeued successfully for immediate delivery.\n", args[0])
		return nil
	},
}

var queueDeleteCmd = &cobra.Command{
	Use:   "delete <queue-id>",
	Short: "Delete a message from the queue (postsuper -d)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		driver := queue.NewSystemDriver("mailopen_postfix")
		svc := queue.NewService(driver)

		if err := svc.Delete(ctx, args[0]); err != nil {
			return fmt.Errorf("failed to delete queue %s: %w", args[0], err)
		}

		fmt.Printf("Message %s deleted from queue.\n", args[0])
		return nil
	},
}

var queueFlushCmd = &cobra.Command{
	Use:   "flush",
	Short: "Attempt delivery of all queued messages immediately (postqueue -f)",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		driver := queue.NewSystemDriver("mailopen_postfix")
		svc := queue.NewService(driver)

		if err := svc.Flush(ctx); err != nil {
			return fmt.Errorf("failed to flush queue: %w", err)
		}

		fmt.Println("Postfix mail queue flush initiated.")
		return nil
	},
}

func init() {
	queueListCmd.Flags().String("status", "", "Filter by status: active, deferred, hold, incoming")

	queueCmd.AddCommand(queueStatusCmd)
	queueCmd.AddCommand(queueListCmd)
	queueCmd.AddCommand(queueInspectCmd)
	queueCmd.AddCommand(queueRetryCmd)
	queueCmd.AddCommand(queueDeleteCmd)
	queueCmd.AddCommand(queueFlushCmd)
}
