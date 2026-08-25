package cli

import (
	"fmt"
	"os"

	"github.com/azdharsyahputra/openmail/internal/config"
	"github.com/azdharsyahputra/openmail/internal/dovecot"
	"github.com/azdharsyahputra/openmail/internal/postfix"
	"github.com/azdharsyahputra/openmail/internal/tls"
	"github.com/spf13/cobra"
)

var (
	tlsHostname string
	tlsCertPath string
	tlsKeyPath  string
)

var tlsCmd = &cobra.Command{
	Use:   "tls",
	Short: "Manage TLS certificates and secure mail configurations",
}

var tlsInstallCmd = &cobra.Command{
	Use:   "install",
	Short: "Install and atomically validate a new TLS certificate and private key",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load()
		if err != nil {
			return err
		}

		hostname := tlsHostname
		if hostname == "" {
			hostname = cfg.TLSHostname
		}

		if tlsCertPath == "" || tlsKeyPath == "" {
			return fmt.Errorf("both --cert and --key flags are required")
		}

		provider := tls.NewFilesystemProvider(cfg.TLSBaseDir)
		svc := tls.NewService(provider)

		report, err := svc.Install(cmd.Context(), hostname, tlsCertPath, tlsKeyPath)
		if err != nil {
			fmt.Printf("Certificate installation FAILED: %v\n", err)
			if report != nil && report.Message != "" {
				fmt.Printf("Details: %s\n", report.Message)
			}
			return err
		}

		fmt.Println("TLS Certificate installed successfully:")
		fmt.Printf("  Hostname:       %s\n", hostname)
		fmt.Printf("  Issuer:         %s\n", report.Issuer)
		fmt.Printf("  Expires:        %s\n", report.NotAfter.Format("2006-01-02"))
		fmt.Printf("  Days Remaining: %d days (%s)\n", report.DaysRemaining, report.Status)
		fmt.Println()

		// Attempt atomic reloads of services
		postfixProv := postfix.NewSystemProvisioner(cfg.PostfixConfigDir)
		_ = postfixProv.Reload(cmd.Context())

		dovecotProv := dovecot.NewSystemProvisioner(cfg.DovecotConfigDir)
		_ = dovecotProv.Reload(cmd.Context())

		fmt.Println("Services notified for live TLS certificate reload")
		return nil
	},
}

var tlsValidateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Validate an installed TLS certificate on the filesystem",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load()
		if err != nil {
			return err
		}

		hostname := tlsHostname
		if hostname == "" {
			hostname = cfg.TLSHostname
		}

		provider := tls.NewFilesystemProvider(cfg.TLSBaseDir)
		report, err := provider.Validate(cmd.Context(), hostname)
		if err != nil {
			fmt.Printf("Validation FAILED: %v\n", err)
			if report != nil && report.Message != "" {
				fmt.Printf("Details: %s\n", report.Message)
			}
			os.Exit(1)
		}

		fmt.Printf("TLS Certificate for %s is VALID (%s)\n", hostname, report.Status)
		return nil
	},
}

var tlsStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show status and expiration of installed TLS certificate",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load()
		if err != nil {
			return err
		}

		hostname := tlsHostname
		if hostname == "" {
			hostname = cfg.TLSHostname
		}

		provider := tls.NewFilesystemProvider(cfg.TLSBaseDir)
		report, err := provider.Validate(cmd.Context(), hostname)

		fmt.Println("TLS Certificate Status")
		fmt.Println("────────────────────────────────")
		fmt.Printf("Hostname       %s\n", hostname)

		if err != nil && (report == nil || !report.Exists) {
			fmt.Println("Certificate    ✗ NOT FOUND")
			fmt.Println("Result: MISSING")
			return nil
		}

		certIcon := "✓"
		if !report.CertificateOK {
			certIcon = "✗"
		}
		keyIcon := "✓"
		if !report.PrivateKeyOK {
			keyIcon = "✗"
		}
		matchIcon := "✓"
		if !report.KeyMatches {
			matchIcon = "✗"
		}
		hostIcon := "✓"
		if !report.HostnameMatches {
			hostIcon = "✗"
		}

		fmt.Printf("Certificate    %s\n", certIcon)
		fmt.Printf("Private Key    %s\n", keyIcon)
		fmt.Printf("Key Match      %s\n", matchIcon)
		fmt.Printf("Hostname       %s\n", hostIcon)
		fmt.Printf("Issuer         %s\n", report.Issuer)
		fmt.Printf("Expires        %s\n", report.NotAfter.Format("2006-01-02"))
		fmt.Printf("Remaining      %d days\n", report.DaysRemaining)
		fmt.Println()

		if report.Status == tls.StatusHealthy {
			fmt.Println("Result: HEALTHY")
		} else if report.Status == tls.StatusWarning {
			fmt.Println("Result: WARNING (Renewal Recommended)")
		} else if report.Status == tls.StatusCritical {
			fmt.Println("Result: CRITICAL (Expiring Soon)")
		} else {
			fmt.Println("Result: EXPIRED / UNHEALTHY")
		}

		return nil
	},
}

var tlsDoctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Run comprehensive TLS diagnostics across certificates, Postfix, and Dovecot",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load()
		if err != nil {
			return err
		}

		hostname := tlsHostname
		if hostname == "" {
			hostname = cfg.TLSHostname
		}

		provider := tls.NewFilesystemProvider(cfg.TLSBaseDir)
		report := tls.RunDoctor(cmd.Context(), provider, hostname, cfg.PostfixConfigDir, cfg.DovecotConfigDir)

		fmt.Println("OpenMail TLS Doctor")
		fmt.Println("══════════════════════════════════")
		fmt.Printf("Target Hostname: %s\n\n", hostname)

		// Group by category
		categories := make(map[string][]tls.CheckItem)
		var catOrder []string
		for _, c := range report.Checks {
			if _, ok := categories[c.Category]; !ok {
				catOrder = append(catOrder, c.Category)
			}
			categories[c.Category] = append(categories[c.Category], c)
		}

		for _, cat := range catOrder {
			fmt.Println(cat)
			for _, item := range categories[cat] {
				icon := "✓"
				if !item.Passed {
					icon = "✗"
				}
				fmt.Printf("  %-26s %s  %s\n", item.Name, icon, item.Message)
			}
			fmt.Println()
		}

		if report.Healthy {
			fmt.Println("Result: HEALTHY")
		} else {
			fmt.Println("Result: UNHEALTHY / ATTENTION REQUIRED")
		}

		return nil
	},
}

func init() {
	tlsCmd.PersistentFlags().StringVar(&tlsHostname, "hostname", "", "TLS Hostname (default from config/env)")

	tlsInstallCmd.Flags().StringVar(&tlsCertPath, "cert", "", "Path to fullchain certificate PEM file")
	tlsInstallCmd.Flags().StringVar(&tlsKeyPath, "key", "", "Path to private key PEM file")

	tlsCmd.AddCommand(tlsInstallCmd)
	tlsCmd.AddCommand(tlsValidateCmd)
	tlsCmd.AddCommand(tlsStatusCmd)
	tlsCmd.AddCommand(tlsDoctorCmd)
}
