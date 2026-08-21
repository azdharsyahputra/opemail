package cli

import (
	"fmt"

	"github.com/azdharsyahputra/openmail/internal/config"
	"github.com/azdharsyahputra/openmail/internal/dovecot"
	"github.com/spf13/cobra"
)

var (
	dovecotConfigOutDir     string
	dovecotTargetConfigPath string
	dovecotAuthPassword     string
)

var dovecotCmd = &cobra.Command{
	Use:   "dovecot",
	Short: "Manage Dovecot IMAP and authentication adapter",
}

var dovecotConfigCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage Dovecot configuration files",
}

var dovecotConfigGenerateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate Dovecot configuration and sql mapping files",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load()
		if err != nil {
			return err
		}

		outDir := dovecotConfigOutDir
		if outDir == "" {
			outDir = cfg.DovecotConfigDir
		}

		opts := dovecot.ConfigOptions{
			ConfigDir:        outDir,
			TargetConfigPath: dovecotTargetConfigPath,
			VmailRoot:        cfg.VmailRoot,
			VmailUID:         cfg.VmailUID,
			VmailGID:         cfg.VmailGID,
			DBHost:           cfg.DovecotDBHost,
			DBPort:           cfg.DovecotDBPort,
			DBName:           cfg.DovecotDBName,
			DBUser:           cfg.DovecotDBUser,
			DBPassword:       cfg.DovecotDBPassword,
			Hostname:         cfg.TLSHostname,
			TLSCertFile:      fmt.Sprintf("/etc/mailopen/tls/%s/fullchain.pem", cfg.TLSHostname),
			TLSKeyFile:       fmt.Sprintf("/etc/mailopen/tls/%s/privkey.pem", cfg.TLSHostname),
		}


		if err := dovecot.WriteConfigsAtomically(opts); err != nil {
			return err
		}

		fmt.Println("Dovecot configuration generated successfully:")
		fmt.Printf("  Target Directory: %s\n", outDir)
		fmt.Println("  Files generated:")
		fmt.Println("    - dovecot.conf")
		fmt.Println("    - conf.d/10-mail.conf")
		fmt.Println("    - conf.d/10-auth.conf")
		fmt.Println("    - conf.d/10-master.conf")
		fmt.Println("    - conf.d/auth-sql.conf.ext")
		fmt.Println("    - sql/dovecot-pgsql.conf.ext")
		return nil
	},
}

var dovecotConfigValidateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Validate Dovecot configuration files syntax using doveconf",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load()
		if err != nil {
			return err
		}

		outDir := dovecotConfigOutDir
		if outDir == "" {
			outDir = cfg.DovecotConfigDir
		}

		prov := dovecot.NewSystemProvisioner(outDir)
		if err := prov.Validate(cmd.Context()); err != nil {
			return fmt.Errorf("dovecot validation failed: %w", err)
		}

		fmt.Println("Dovecot configuration is VALID")
		return nil
	},
}

var dovecotReloadCmd = &cobra.Command{
	Use:   "reload",
	Short: "Reload Dovecot service",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load()
		if err != nil {
			return err
		}

		prov := dovecot.NewSystemProvisioner(cfg.DovecotConfigDir)
		if err := prov.Reload(cmd.Context()); err != nil {
			return err
		}

		fmt.Println("Dovecot reloaded successfully")
		return nil
	},
}

var dovecotDoctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Run diagnostics and health check for Dovecot integration",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load()
		if err != nil {
			return err
		}

		outDir := dovecotConfigOutDir
		if outDir == "" {
			outDir = cfg.DovecotConfigDir
		}

		report := dovecot.RunDoctor(cmd.Context(), dovecotRepo, outDir, cfg.VmailRoot, cfg.VmailUID, cfg.VmailGID)

		fmt.Println("Dovecot Doctor")
		fmt.Println("────────────────────────────")
		fmt.Println()

		categories := []struct {
			name   string
			checks []dovecot.CheckItem
		}{
			{"Service", report.ServiceChecks},
			{"Configuration", report.ConfigChecks},
			{"Database", report.DatabaseChecks},
			{"Filesystem", report.FilesystemChecks},
			{"Protocols", report.ProtocolChecks},
		}

		for _, cat := range categories {
			fmt.Println(cat.name)
			for _, c := range cat.checks {
				icon := "✓"
				if !c.Passed {
					icon = "✗"
				}
				fmt.Printf("  %-30s %s  %s\n", c.Name, icon, c.Message)
			}
			fmt.Println()
		}

		if report.Healthy {
			fmt.Println("Result: HEALTHY")
		} else {
			fmt.Println("Result: ATTENTION REQUIRED")
		}

		return nil
	},
}

var dovecotLookupCmd = &cobra.Command{
	Use:   "lookup",
	Short: "Perform Dovecot userdb lookup simulations",
}

var dovecotLookupUserCmd = &cobra.Command{
	Use:   "user <email>",
	Short: "Simulate Dovecot userdb lookup for a mailbox user",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		email := args[0]
		cfg, err := config.Load()
		if err != nil {
			return err
		}

		info, err := dovecotService.GetUserInfo(cmd.Context(), email, cfg.VmailRoot, cfg.VmailUID, cfg.VmailGID)
		if err != nil {
			return err
		}

		fmt.Printf("User:         %s\n", info.Username)
		fmt.Printf("Status:       %s\n", info.Status)
		fmt.Printf("Provisioning: %s\n", info.ProvisioningStatus)
		fmt.Printf("UID:          %d\n", info.UID)
		fmt.Printf("GID:          %d\n", info.GID)
		fmt.Printf("Maildir:      %s\n", info.Home)
		return nil
	},
}

var dovecotAuthCmd = &cobra.Command{
	Use:   "auth",
	Short: "Test authentication for a user",
}

var dovecotAuthTestCmd = &cobra.Command{
	Use:   "test <email>",
	Short: "Simulate Dovecot passdb authentication against Argon2id hash",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		email := args[0]
		if dovecotAuthPassword == "" {
			return fmt.Errorf("please provide password via --password")
		}

		err := dovecotService.Authenticate(cmd.Context(), email, dovecotAuthPassword)
		if err != nil {
			fmt.Println("Authentication: FAILED")
			return nil
		}

		fmt.Println("Authentication: SUCCESS")
		return nil
	},
}

func init() {
	dovecotConfigGenerateCmd.Flags().StringVar(&dovecotConfigOutDir, "out-dir", "", "Custom output directory for generated Dovecot configs")
	dovecotConfigGenerateCmd.Flags().StringVar(&dovecotTargetConfigPath, "target-path", "", "Target config path prefix used in dovecot.conf")
	dovecotConfigValidateCmd.Flags().StringVar(&dovecotConfigOutDir, "out-dir", "", "Custom directory to validate")
	dovecotDoctorCmd.Flags().StringVar(&dovecotConfigOutDir, "out-dir", "", "Custom directory to inspect")

	dovecotAuthTestCmd.Flags().StringVarP(&dovecotAuthPassword, "password", "p", "", "Password to test authentication")

	dovecotConfigCmd.AddCommand(dovecotConfigGenerateCmd)
	dovecotConfigCmd.AddCommand(dovecotConfigValidateCmd)

	dovecotLookupCmd.AddCommand(dovecotLookupUserCmd)
	dovecotAuthCmd.AddCommand(dovecotAuthTestCmd)

	dovecotCmd.AddCommand(dovecotConfigCmd)
	dovecotCmd.AddCommand(dovecotReloadCmd)
	dovecotCmd.AddCommand(dovecotDoctorCmd)
	dovecotCmd.AddCommand(dovecotLookupCmd)
	dovecotCmd.AddCommand(dovecotAuthCmd)
}
