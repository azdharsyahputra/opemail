package cli

import (
	"fmt"
	"strings"

	"github.com/azdharsyahputra/openmail/internal/config"
	"github.com/azdharsyahputra/openmail/internal/postfix"
	"github.com/spf13/cobra"
)

var (
	postfixConfigOutDir       string
	postfixTargetConfigPath   string
)


var postfixCmd = &cobra.Command{
	Use:   "postfix",
	Short: "Manage Postfix MTA adapter and configuration",
}

var postfixConfigCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage Postfix configuration files",
}

var postfixConfigGenerateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate Postfix main.cf and pgsql-*.cf map configuration files",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load()
		if err != nil {
			return err
		}

		outDir := postfixConfigOutDir
		if outDir == "" {
			outDir = cfg.PostfixConfigDir
		}

		opts := postfix.ConfigOptions{
			ConfigDir:        outDir,
			TargetConfigPath: postfixTargetConfigPath,
			Hostname:         cfg.PostfixHostname,
			VmailRoot:        cfg.VmailRoot,
			VmailUID:         cfg.VmailUID,
			VmailGID:         cfg.VmailGID,
			DBHost:           cfg.PostfixDBHost,
			DBPort:           cfg.PostfixDBPort,
			DBName:           cfg.PostfixDBName,
			DBUser:           cfg.PostfixDBUser,
			DBPassword:       cfg.PostfixDBPassword,
		}

		if err := postfix.WriteConfigsAtomically(opts); err != nil {
			return err
		}


		fmt.Println("Postfix configuration generated successfully:")
		fmt.Printf("  Target Directory: %s\n", outDir)
		fmt.Println("  Files generated:")
		fmt.Println("    - main.cf")
		fmt.Println("    - pgsql-virtual-mailbox-domains.cf")
		fmt.Println("    - pgsql-virtual-mailbox-maps.cf")
		fmt.Println("    - pgsql-virtual-alias-maps.cf")
		return nil
	},
}

var postfixConfigValidateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Validate Postfix configuration files and syntax",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load()
		if err != nil {
			return err
		}

		outDir := postfixConfigOutDir
		if outDir == "" {
			outDir = cfg.PostfixConfigDir
		}

		prov := postfix.NewSystemProvisioner(outDir)
		if err := prov.Validate(cmd.Context()); err != nil {
			return fmt.Errorf("postfix validation failed: %w", err)
		}

		fmt.Println("Postfix configuration is VALID")
		return nil
	},
}

var postfixReloadCmd = &cobra.Command{
	Use:   "reload",
	Short: "Reload Postfix service",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load()
		if err != nil {
			return err
		}

		prov := postfix.NewSystemProvisioner(cfg.PostfixConfigDir)
		if err := prov.Reload(cmd.Context()); err != nil {
			return err
		}

		fmt.Println("Postfix reloaded successfully")
		return nil
	},
}

var postfixDoctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Run diagnostics and check health of Postfix integration",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load()
		if err != nil {
			return err
		}

		outDir := postfixConfigOutDir
		if outDir == "" {
			outDir = cfg.PostfixConfigDir
		}

		report := postfix.RunDoctor(cmd.Context(), postfixRepo, outDir, cfg.VmailRoot, cfg.VmailUID, cfg.VmailGID)

		fmt.Println("Postfix Doctor")
		fmt.Println("──────────────────────────────────────────────")
		fmt.Println()
		for _, c := range report.Checks {
			icon := "✓"
			if !c.Passed {
				icon = "✗"
			}
			fmt.Printf("  %-32s %s  (%s)\n", c.Name, icon, c.Message)
		}
		fmt.Println()
		if report.Healthy {
			fmt.Println("Result: HEALTHY")
		} else {
			fmt.Println("Result: UNHEALTHY / ATTENTION REQUIRED")
		}

		return nil
	},
}

var postfixLookupCmd = &cobra.Command{
	Use:   "lookup",
	Short: "Perform live PostgreSQL lookup simulations",
}

var postfixLookupDomainCmd = &cobra.Command{
	Use:   "domain <name>",
	Short: "Test virtual_mailbox_domains lookup for a domain",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		domainName := args[0]
		found, err := postfixRepo.LookupVirtualDomain(cmd.Context(), domainName)
		if err != nil {
			return err
		}

		if found {
			fmt.Printf("Domain: %s -> FOUND (1)\n", domainName)
		} else {
			fmt.Printf("Domain: %s -> NOT FOUND (0)\n", domainName)
		}
		return nil
	},
}

var postfixLookupMailboxCmd = &cobra.Command{
	Use:   "mailbox <email>",
	Short: "Test virtual_mailbox_maps lookup for a mailbox",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		email := args[0]
		found, err := postfixRepo.LookupVirtualMailbox(cmd.Context(), email)
		if err != nil {
			return err
		}

		if found {
			fmt.Printf("Mailbox: %s -> FOUND (1)\n", email)
		} else {
			fmt.Printf("Mailbox: %s -> NOT FOUND (0 / inactive or not ready)\n", email)
		}
		return nil
	},
}

var postfixLookupAliasCmd = &cobra.Command{
	Use:   "alias <source-email>",
	Short: "Test virtual_alias_maps lookup for an alias",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		source := args[0]
		destinations, err := postfixRepo.LookupVirtualAlias(cmd.Context(), source)
		if err != nil {
			return err
		}

		if len(destinations) > 0 {
			fmt.Printf("Alias: %s -> %s\n", source, strings.Join(destinations, ", "))
		} else {
			fmt.Printf("Alias: %s -> NOT FOUND\n", source)
		}
		return nil
	},
}

func init() {
	postfixConfigGenerateCmd.Flags().StringVar(&postfixConfigOutDir, "out-dir", "", "Custom target output directory for config files")
	postfixConfigGenerateCmd.Flags().StringVar(&postfixTargetConfigPath, "target-path", "", "Target config path prefix used in main.cf (e.g. /etc/postfix)")
	postfixConfigValidateCmd.Flags().StringVar(&postfixConfigOutDir, "out-dir", "", "Custom target directory to validate")

	postfixDoctorCmd.Flags().StringVar(&postfixConfigOutDir, "out-dir", "", "Custom target directory to inspect")

	postfixConfigCmd.AddCommand(postfixConfigGenerateCmd)
	postfixConfigCmd.AddCommand(postfixConfigValidateCmd)

	postfixLookupCmd.AddCommand(postfixLookupDomainCmd)
	postfixLookupCmd.AddCommand(postfixLookupMailboxCmd)
	postfixLookupCmd.AddCommand(postfixLookupAliasCmd)

	postfixCmd.AddCommand(postfixConfigCmd)
	postfixCmd.AddCommand(postfixReloadCmd)
	postfixCmd.AddCommand(postfixDoctorCmd)
	postfixCmd.AddCommand(postfixLookupCmd)
}
