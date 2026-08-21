package cli

import (
	"fmt"
	"io"
	"os"
	"text/tabwriter"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
)

var messageCmd = &cobra.Command{
	Use:   "message",
	Short: "Manage email messages",
}

var messageListCmd = &cobra.Command{
	Use:   "list <email>",
	Short: "List messages in a mailbox",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		email := args[0]
		messages, err := messageService.ListByMailbox(cmd.Context(), email)
		if err != nil {
			return err
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 4, ' ', 0)
		fmt.Fprintln(w, "ID\tSENDER\tSUBJECT\tSIZE\tRECEIVED AT")
		for _, m := range messages {
			fmt.Fprintf(w, "%s\t%s\t%s\t%d B\t%s\n",
				m.ID, m.Sender, m.Subject, m.SizeBytes, m.ReceivedAt.Format("2006-01-02 15:04:05"))
		}
		w.Flush()
		return nil
	},
}

var messageStoreCmd = &cobra.Command{
	Use:   "store <email> [filepath]",
	Short: "Store a raw email into a mailbox (reads from file or stdin if omitted)",
	Args:  cobra.RangeArgs(1, 2),
	RunE: func(cmd *cobra.Command, args []string) error {
		email := args[0]

		var r io.Reader
		if len(args) == 2 {
			file, err := os.Open(args[1])
			if err != nil {
				return fmt.Errorf("failed to open file: %w", err)
			}
			defer file.Close()
			r = file
		} else {
			r = os.Stdin
		}

		msg, err := messageService.Store(cmd.Context(), email, r)
		if err != nil {
			return err
		}

		fmt.Println("Message stored successfully")
		fmt.Println()
		fmt.Printf("ID:          %s\n", msg.ID)
		fmt.Printf("Blob ID:     %s\n", msg.BlobID)
		fmt.Printf("Sender:      %s\n", msg.Sender)
		fmt.Printf("Subject:     %s\n", msg.Subject)
		fmt.Printf("Size:        %d bytes\n", msg.SizeBytes)
		fmt.Printf("Received At: %s\n", msg.ReceivedAt.Format("2006-01-02 15:04:05"))
		return nil
	},
}

var messageGetCmd = &cobra.Command{
	Use:   "get <id>",
	Short: "Get message metadata and raw content",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		id, err := uuid.Parse(args[0])
		if err != nil {
			return fmt.Errorf("invalid message UUID: %w", err)
		}

		msg, reader, err := messageService.GetContent(cmd.Context(), id)
		if err != nil {
			return err
		}
		defer reader.Close()

		fmt.Printf("Message ID:  %s\n", msg.ID)
		fmt.Printf("Blob ID:     %s\n", msg.BlobID)
		fmt.Printf("Sender:      %s\n", msg.Sender)
		fmt.Printf("Subject:     %s\n", msg.Subject)
		fmt.Printf("Size:        %d bytes\n", msg.SizeBytes)
		fmt.Printf("Received At: %s\n", msg.ReceivedAt.Format("2006-01-02 15:04:05"))
		fmt.Println("\n--- RAW PAYLOAD ---")

		_, err = io.Copy(os.Stdout, reader)
		fmt.Println()
		return err
	},
}

var messageDeleteCmd = &cobra.Command{
	Use:   "delete <id>",
	Short: "Delete a message by ID",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		id, err := uuid.Parse(args[0])
		if err != nil {
			return fmt.Errorf("invalid message UUID: %w", err)
		}

		if err := messageService.Delete(cmd.Context(), id); err != nil {
			return err
		}

		fmt.Printf("Message %s deleted successfully\n", id)
		return nil
	},
}

func init() {
	messageCmd.AddCommand(messageListCmd)
	messageCmd.AddCommand(messageStoreCmd)
	messageCmd.AddCommand(messageGetCmd)
	messageCmd.AddCommand(messageDeleteCmd)
}
