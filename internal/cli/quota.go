package cli

import (
	"fmt"

	"github.com/azdharsyahputra/openmail/internal/mailbox"
	"github.com/azdharsyahputra/openmail/internal/provisioning"
	"github.com/azdharsyahputra/openmail/internal/quota"
	"github.com/spf13/cobra"
)

var quotaCmd = &cobra.Command{
	Use:   "quota",
	Short: "Inspect and reconcile mailbox storage quotas",
}

var quotaShowCmd = &cobra.Command{
	Use:   "show <email>",
	Short: "Show current quota usage and status for a mailbox",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		db, err := getDB()
		if err != nil {
			return err
		}
		defer db.Close()

		mbRepo := mailbox.NewPostgresRepository(db)
		qSvc := quota.NewService(mbRepo, nil)

		q, err := qSvc.GetQuota(ctx, args[0])
		if err != nil {
			return fmt.Errorf("failed to get quota: %w", err)
		}

		fmt.Println("\nMailbox Quota")
		fmt.Println("────────────────────────────")
		fmt.Printf("Email:        %s\n", q.Email)
		fmt.Printf("Used:         %.2f MB (%d bytes)\n", float64(q.UsedBytes)/(1024*1024), q.UsedBytes)
		fmt.Printf("Quota:        %.2f MB (%d bytes)\n", float64(q.QuotaBytes)/(1024*1024), q.QuotaBytes)
		fmt.Printf("Usage:        %.1f%%\n", q.UsagePercent)
		fmt.Printf("Status:       %s\n", q.Status)
		fmt.Printf("Full/Exceeded:%t\n", q.IsExceeded)
		return nil
	},
}

var quotaReconcileCmd = &cobra.Command{
	Use:   "reconcile <email>",
	Short: "Scan Maildir on disk and synchronize database quota counter",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		db, err := getDB()
		if err != nil {
			return err
		}
		defer db.Close()

		cfg, _ := loadAppConfig()
		mbRepo := mailbox.NewPostgresRepository(db)
		prov, _ := provisioning.NewFilesystemProvisioner(cfg.VmailRoot, cfg.VmailUID, cfg.VmailGID)
		qSvc := quota.NewService(mbRepo, prov)


		q, err := qSvc.Reconcile(ctx, args[0])
		if err != nil {
			return fmt.Errorf("failed to reconcile quota: %w", err)
		}

		fmt.Println("\nQuota Reconciled Successfully")
		fmt.Println("────────────────────────────")
		fmt.Printf("Email:         %s\n", q.Email)
		fmt.Printf("Actual Used:   %.2f MB (%d bytes)\n", float64(q.UsedBytes)/(1024*1024), q.UsedBytes)
		fmt.Printf("Message Count: %d\n", q.MessageCount)
		fmt.Printf("Usage:         %.1f%%\n", q.UsagePercent)
		fmt.Printf("Status:        %s\n", q.Status)
		return nil
	},
}

func init() {
	quotaCmd.AddCommand(quotaShowCmd)
	quotaCmd.AddCommand(quotaReconcileCmd)
}
