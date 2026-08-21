package cli

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/azdharsyahputra/openmail/internal/audit"
	"github.com/spf13/cobra"
)

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Inspect administrator and system audit trail logs",
}

var auditListCmd = &cobra.Command{
	Use:   "list",
	Short: "List administrative and system activity logs",
	RunE: func(cmd *cobra.Command, args []string) error {
		limit, _ := cmd.Flags().GetInt("limit")
		if limit <= 0 {
			limit = 50
		}

		db, err := getDB()
		if err != nil {
			return err
		}
		defer db.Close()

		auditRepo := audit.NewPostgresRepository(db)
		auditSvc := audit.NewService(auditRepo)

		logs, err := auditSvc.ListAuditLogs(cmd.Context(), limit)
		if err != nil {
			return fmt.Errorf("failed to list audit logs: %w", err)
		}

		if len(logs) == 0 {
			fmt.Println("No audit logs recorded yet.")
			return nil
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
		fmt.Fprintln(w, "TIMESTAMP\tACTOR\tACTION\tRESOURCE\tMETADATA")
		for _, l := range logs {
			metaStr := string(l.Metadata)
			if len(metaStr) > 40 {
				metaStr = metaStr[:37] + "..."
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
				l.CreatedAt.Format("2006-01-02 15:04:05"),
				l.ActorType,
				l.Action,
				l.ResourceType,
				metaStr,
			)
		}
		return w.Flush()
	},
}

func init() {
	auditListCmd.Flags().Int("limit", 50, "Maximum number of audit log entries to return")

	auditCmd.AddCommand(auditListCmd)
}
