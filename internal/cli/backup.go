package cli

import (
	"fmt"

	"github.com/azdharsyahputra/openmail/internal/backup"
	"github.com/spf13/cobra"
)

var backupCmd = &cobra.Command{
	Use:   "backup",
	Short: "Create, verify, and restore full system backups",
}

var backupCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create an encrypted complete backup archive (PostgreSQL + Maildir + Keys + Configs)",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		db, _ := getDB()
		if db != nil {
			defer db.Close()
		}

		cfg, _ := loadAppConfig()
		outPath, _ := cmd.Flags().GetString("out")
		passphrase, _ := cmd.Flags().GetString("passphrase")

		bCfg := backup.BackupConfig{
			DB:         db,
			VmailDir:   cfg.VmailRoot,
			DKIMDir:    cfg.DKIMBaseDir,
			TLSDir:     cfg.TLSBaseDir,
			ConfigDir:  cfg.PostfixConfigDir,
			Passphrase: passphrase,
			OutputPath: outPath,
		}


		manifest, finalPath, err := backup.CreateBackup(ctx, bCfg)
		if err != nil {
			return fmt.Errorf("backup failed: %w", err)
		}

		fmt.Println("\nBackup Created Successfully")
		fmt.Println("────────────────────────────")
		fmt.Printf("File:        %s\n", finalPath)
		fmt.Printf("Size:        %.2f MB (%d bytes)\n", float64(manifest.ArchiveBytes)/(1024*1024), manifest.ArchiveBytes)
		fmt.Printf("Encrypted:   %t\n", manifest.Encrypted)
		fmt.Printf("Total Files: %d\n", manifest.TotalFiles)
		fmt.Printf("PostgreSQL:  %t\n", manifest.Database)
		fmt.Printf("Maildir:     %t\n", manifest.Maildir)
		fmt.Printf("DKIM Keys:   %t\n", manifest.DKIM)
		fmt.Printf("TLS Keys:    %t\n", manifest.TLS)
		return nil
	},
}

var backupVerifyCmd = &cobra.Command{
	Use:   "verify <archive-file>",
	Short: "Verify the integrity, checksums, and decryptability of a backup archive",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		passphrase, _ := cmd.Flags().GetString("passphrase")
		report, err := backup.VerifyBackup(args[0], passphrase)
		if err != nil {
			return fmt.Errorf("verify failed: %w", err)
		}

		fmt.Println("\nBackup Verification Report")
		fmt.Println("────────────────────────────")
		fmt.Printf("File:      %s\n", args[0])
		fmt.Printf("Valid:     %t\n", report.Valid)
		fmt.Printf("Files:     %d\n", report.FileCount)
		fmt.Printf("Encrypted: %t\n", report.Manifest.Encrypted)
		if len(report.Errors) > 0 {
			fmt.Println("\nErrors:")
			for _, e := range report.Errors {
				fmt.Printf("  ✗ %s\n", e)
			}
		}
		return nil
	},
}

var backupRestoreCmd = &cobra.Command{
	Use:   "restore <archive-file>",
	Short: "Restore archive contents to destination directory",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		passphrase, _ := cmd.Flags().GetString("passphrase")
		targetDir, _ := cmd.Flags().GetString("target-dir")
		if targetDir == "" {
			targetDir = "restored_data"
		}

		res, err := backup.RestoreBackup(ctx, args[0], passphrase, targetDir)
		if err != nil {
			return fmt.Errorf("restore failed: %w", err)
		}

		fmt.Println("\nBackup Restored Successfully")
		fmt.Println("────────────────────────────")
		fmt.Printf("Target Directory: %s\n", res.TargetDir)
		fmt.Printf("Files Restored:   %d\n", res.FilesRestored)
		return nil
	},
}

func init() {
	backupCreateCmd.Flags().String("out", "", "Output file path")
	backupCreateCmd.Flags().String("passphrase", "", "Passphrase for AES-256-GCM encryption")

	backupVerifyCmd.Flags().String("passphrase", "", "Passphrase for encrypted archive")

	backupRestoreCmd.Flags().String("passphrase", "", "Passphrase for encrypted archive")
	backupRestoreCmd.Flags().String("target-dir", "restored_data", "Destination directory to unpack contents")

	backupCmd.AddCommand(backupCreateCmd)
	backupCmd.AddCommand(backupVerifyCmd)
	backupCmd.AddCommand(backupRestoreCmd)
}
