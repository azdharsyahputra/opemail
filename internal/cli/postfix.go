package cli

import (
	"fmt"
	"net"
	"net/smtp"
	"strings"
	"time"

	"github.com/azdharsyahputra/openmail/internal/config"
	"github.com/azdharsyahputra/openmail/internal/dkim"
	"github.com/azdharsyahputra/openmail/internal/postfix"
	"github.com/spf13/cobra"

)



var (
	postfixConfigOutDir     string
	postfixTargetConfigPath string
	submissionAuthPassword  string
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
	Short: "Generate Postfix main.cf, master.cf, and pgsql-*.cf map configuration files",
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
			TLSCertFile:      fmt.Sprintf("/etc/mailopen/tls/%s/fullchain.pem", cfg.TLSHostname),
			TLSKeyFile:       fmt.Sprintf("/etc/mailopen/tls/%s/privkey.pem", cfg.TLSHostname),
		}


		if err := postfix.WriteConfigsAtomically(opts); err != nil {
			return err
		}

		fmt.Println("Postfix configuration generated successfully:")
		fmt.Printf("  Target Directory: %s\n", outDir)
		fmt.Println("  Files generated:")
		fmt.Println("    - main.cf")
		fmt.Println("    - master.cf (inbound :25 & submission :587)")
		fmt.Println("    - pgsql-virtual-mailbox-domains.cf")
		fmt.Println("    - pgsql-virtual-mailbox-maps.cf")
		fmt.Println("    - pgsql-virtual-alias-maps.cf")
		fmt.Println("    - pgsql-sender-login-maps.cf")
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

// Submission Subcommands (W2.6)
var postfixSubmissionCmd = &cobra.Command{
	Use:   "submission",
	Short: "Manage Postfix submission (:587) and SMTP AUTH adapter",
}

var postfixSubmissionConfigCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage Postfix submission configuration",
}

var postfixSubmissionDoctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Run diagnostics and check health of Postfix submission (:587)",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load()
		if err != nil {
			return err
		}

		outDir := postfixConfigOutDir
		if outDir == "" {
			outDir = cfg.PostfixConfigDir
		}

		authorizer := postfix.NewPostgresSenderAuthorizer(db)
		report := postfix.RunSubmissionDoctor(cmd.Context(), postfixRepo, authorizer, outDir)

		fmt.Println("Postfix Submission Doctor")
		fmt.Println("────────────────────────────────")
		fmt.Println()

		categories := []struct {
			name   string
			checks []postfix.CheckItem
		}{
			{"Postfix", report.PostfixChecks},
			{"Listener", report.ListenerChecks},
			{"SASL", report.SASLChecks},
			{"Authentication", report.AuthenticationChecks},
			{"Relay Policy", report.RelayPolicyChecks},
			{"Security", report.SecurityChecks},
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

var postfixSubmissionStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Check Postfix submission :587 listener status",
	RunE: func(cmd *cobra.Command, args []string) error {
		conn, err := net.DialTimeout("tcp", "127.0.0.1:587", 1*time.Second)
		if err != nil {
			fmt.Println("Submission Status: STOPPED / UNREACHABLE")
			return nil
		}
		defer conn.Close()
		fmt.Println("Submission Status: RUNNING (127.0.0.1:587 listening)")
		return nil
	},
}

type plainAuthWithoutTLS struct {
	username, password string
}

func (a *plainAuthWithoutTLS) Start(server *smtp.ServerInfo) (string, []byte, error) {
	resp := []byte("\x00" + a.username + "\x00" + a.password)
	return "PLAIN", resp, nil
}

func (a *plainAuthWithoutTLS) Next(fromServer []byte, more bool) ([]byte, error) {
	return nil, nil
}

var postfixSubmissionAuthTestCmd = &cobra.Command{
	Use:   "auth-test <email>",
	Short: "Test SMTP AUTH on 127.0.0.1:587 against Dovecot SASL & PostgreSQL",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		email := args[0]
		if submissionAuthPassword == "" {
			return fmt.Errorf("please provide password via --password")
		}

		fmt.Println("SMTP AUTH Test")
		fmt.Println("────────────────────────")
		fmt.Println("Server       127.0.0.1:587")
		fmt.Printf("Username     %s\n", email)
		fmt.Println("Mechanism    PLAIN")
		fmt.Println()

		c, err := smtp.Dial("127.0.0.1:587")
		if err != nil {
			fmt.Printf("Connection error: %v\n", err)
			fmt.Println("Authentication: FAILED")
			return nil
		}
		defer c.Close()

		auth := &plainAuthWithoutTLS{
			username: email,
			password: submissionAuthPassword,
		}

		if err := c.Auth(auth); err != nil {
			fmt.Println("Authentication: FAILED")
			return nil
		}

		fmt.Println("Authentication: SUCCESS")
		return nil
	},
}

var postfixDKIMCmd = &cobra.Command{
	Use:   "dkim",
	Short: "Postfix DKIM milter status and OpenDKIM configuration",
}

var postfixDKIMStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Check Postfix OpenDKIM milter socket status",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load()
		if err != nil {
			return err
		}

		fmt.Println("Postfix OpenDKIM Milter Status")
		fmt.Println("────────────────────────────────")
		fmt.Printf("Socket Path:  %s\n", cfg.OpenDKIMSocket)

		ok, msg := dkim.CheckMilterSocket(cfg.OpenDKIMSocket)
		if ok {
			fmt.Println("Socket:       ✓ AVAILABLE")
			fmt.Println("Milter State: READY (Signing outbound)")
		} else {
			fmt.Printf("Socket:       ✗ %s\n", msg)
			fmt.Println("Milter State: NOT REACHABLE")
		}
		return nil
	},
}

var postfixDKIMGenerateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate OpenDKIM configuration, KeyTable, and SigningTable",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load()
		if err != nil {
			return err
		}

		domains, err := domainService.List(cmd.Context())
		if err != nil {
			return err
		}

		var activeKeys []*dkim.DKIMKey
		for _, d := range domains {
			keys, err := dkimService.ListKeys(cmd.Context(), d.Name)
			if err == nil {
				activeKeys = append(activeKeys, keys...)
			}
		}

		opts := dkim.OpenDKIMConfigOptions{
			ConfigDir:    cfg.OpenDKIMConfigDir,
			DKIMBaseDir:  "/etc/mailopen/dkim",
			SocketPath:   cfg.OpenDKIMSocket,
			ActiveKeys:   activeKeys,
			TrustedHosts: []string{"127.0.0.1", "::1", "localhost", cfg.PostfixHostname},
		}

		if err := dkim.WriteOpenDKIMConfigsAtomically(opts); err != nil {
			return err
		}

		fmt.Println("OpenDKIM configuration generated successfully:")
		fmt.Printf("  Target Directory: %s\n", cfg.OpenDKIMConfigDir)
		fmt.Println("  Files generated:")
		fmt.Println("    - opendkim.conf")
		fmt.Println("    - KeyTable")
		fmt.Println("    - SigningTable")
		fmt.Println("    - TrustedHosts")
		return nil
	},
}


func init() {
	postfixConfigGenerateCmd.Flags().StringVar(&postfixConfigOutDir, "out-dir", "", "Custom target output directory for config files")
	postfixConfigGenerateCmd.Flags().StringVar(&postfixTargetConfigPath, "target-path", "", "Target config path prefix used in main.cf (e.g. /etc/postfix)")
	postfixConfigValidateCmd.Flags().StringVar(&postfixConfigOutDir, "out-dir", "", "Custom target directory to validate")

	postfixDoctorCmd.Flags().StringVar(&postfixConfigOutDir, "out-dir", "", "Custom target directory to inspect")
	postfixSubmissionDoctorCmd.Flags().StringVar(&postfixConfigOutDir, "out-dir", "", "Custom target directory to inspect")

	postfixSubmissionAuthTestCmd.Flags().StringVarP(&submissionAuthPassword, "password", "p", "", "Password for SMTP AUTH")

	postfixConfigCmd.AddCommand(postfixConfigGenerateCmd)
	postfixConfigCmd.AddCommand(postfixConfigValidateCmd)

	postfixLookupCmd.AddCommand(postfixLookupDomainCmd)
	postfixLookupCmd.AddCommand(postfixLookupMailboxCmd)
	postfixLookupCmd.AddCommand(postfixLookupAliasCmd)

	postfixSubmissionConfigCmd.AddCommand(postfixConfigGenerateCmd)
	postfixSubmissionConfigCmd.AddCommand(postfixConfigValidateCmd)

	postfixSubmissionCmd.AddCommand(postfixSubmissionConfigCmd)
	postfixSubmissionCmd.AddCommand(postfixSubmissionDoctorCmd)
	postfixSubmissionCmd.AddCommand(postfixSubmissionStatusCmd)
	postfixSubmissionCmd.AddCommand(postfixSubmissionAuthTestCmd)

	postfixDKIMCmd.AddCommand(postfixDKIMStatusCmd)
	postfixDKIMCmd.AddCommand(postfixDKIMGenerateCmd)

	postfixCmd.AddCommand(postfixConfigCmd)
	postfixCmd.AddCommand(postfixReloadCmd)
	postfixCmd.AddCommand(postfixDoctorCmd)
	postfixCmd.AddCommand(postfixLookupCmd)
	postfixCmd.AddCommand(postfixSubmissionCmd)
	postfixCmd.AddCommand(postfixDKIMCmd)
}


