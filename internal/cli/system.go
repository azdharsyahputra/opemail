package cli

import (
	"fmt"

	"github.com/azdharsyahputra/openmail/internal/queue"
	"github.com/azdharsyahputra/openmail/internal/system"
	"github.com/spf13/cobra"
)

var systemCmd = &cobra.Command{
	Use:   "system",
	Short: "System diagnostic and configuration tools",
}

var systemDoctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Run comprehensive 10-category MailOpen system health diagnostics",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		db, _ := getDB()
		if db != nil {
			defer db.Close()
		}

		cfg, _ := loadAppConfig()
		qDriver := queue.NewSystemDriver("mailopen_postfix")
		qSvc := queue.NewService(qDriver)

		deps := system.SystemDoctorDeps{
			DB:           db,
			QueueService: qSvc,
			VmailDir:     cfg.VmailRoot,
			TLSPath:      cfg.TLSBaseDir,
			DKIMPath:     cfg.DKIMBaseDir,
		}

		report := system.RunSystemDoctor(ctx, deps)

		fmt.Println("\nMailOpen System Doctor")
		fmt.Println("══════════════════════════════════════")

		categories := []string{"DATABASE", "MAIL TRANSPORT", "MAIL ACCESS", "SECURITY", "STORAGE", "OBSERVABILITY", "BACKUP", "QUEUE", "CERTIFICATES"}
		for _, cat := range categories {
			data, exists := report.Categories[cat]
			if !exists {
				continue
			}
			fmt.Printf("\n%s\n", cat)
			for k, v := range data.Checks {
				fmt.Printf("  %-25s  %s\n", k, v)
			}
		}

		fmt.Println("\n──────────────────────────────────────")
		if report.Healthy {
			fmt.Println("Result: HEALTHY")
		} else {
			fmt.Println("Result: UNHEALTHY / ISSUES DETECTED")
		}
		return nil
	},
}

var configValidateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Validate configuration and subsystem permissions across all components",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		db, _ := getDB()
		if db != nil {
			defer db.Close()
		}
		cfg, _ := loadAppConfig()

		report := system.ValidateAllConfigs(ctx, db, cfg.VmailRoot, cfg.TLSBaseDir, cfg.DKIMBaseDir)


		fmt.Println("\nConfiguration Validation Report")
		fmt.Println("────────────────────────────────────────")
		for _, item := range report.Items {
			statusIcon := "✓"
			if !item.Passed {
				statusIcon = "✗"
			}
			fmt.Printf("  %-20s  %s  %s\n", item.Subsystem, statusIcon, item.Message)
		}
		fmt.Println("────────────────────────────────────────")
		if report.Valid {
			fmt.Println("Result: VALID")
		} else {
			fmt.Println("Result: INVALID / ERRORS FOUND")
		}
		return nil
	},
}

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage and validate configurations",
}

func init() {
	systemCmd.AddCommand(systemDoctorCmd)

	configCmd.AddCommand(configValidateCmd)
}
