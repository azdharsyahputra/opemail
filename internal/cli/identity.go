package cli

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/azdharsyahputra/openmail/internal/config"
	"github.com/azdharsyahputra/openmail/internal/database"
	"github.com/azdharsyahputra/openmail/internal/domain"
	"github.com/azdharsyahputra/openmail/internal/identity"
	"github.com/azdharsyahputra/openmail/internal/identity/ldap"
	"github.com/azdharsyahputra/openmail/internal/identity/local"
	"github.com/azdharsyahputra/openmail/internal/mailbox"
	"github.com/azdharsyahputra/openmail/internal/provisioning"
	"github.com/spf13/cobra"
)

func initIdentityService(cfg *config.Config) (identity.Service, error) {
	db, err := database.NewPostgresDB(cfg.DatabaseURL)
	if err != nil {
		return nil, fmt.Errorf("connect to database: %w", err)
	}

	domRepo := domain.NewPostgresRepository(db)
	mbRepo := mailbox.NewPostgresRepository(db)
	prov, _ := provisioning.NewFilesystemProvisioner(cfg.VmailDir, cfg.VmailUID, cfg.VmailGID)
	mbSvc := mailbox.NewService(mbRepo, domRepo, prov)

	localProv := local.NewProvider(mbRepo)
	ldapCfg := ldap.DefaultConfig()
	if cfg.LDAPURL != "" {
		ldapCfg.URL = cfg.LDAPURL
		ldapCfg.BaseDN = cfg.LDAPBaseDN
		ldapCfg.BindDN = cfg.LDAPBindDN
		ldapCfg.BindPassword = cfg.LDAPBindPassword
	}
	ldapProv := ldap.NewProvider(ldapCfg, nil)

	providers := map[string]identity.IdentityProvider{
		"local": localProv,
		"ldap":  ldapProv,
	}

	defaultProvider := "local"
	if cfg.IdentityProvider != "" {
		defaultProvider = cfg.IdentityProvider
	}

	return identity.NewService(defaultProvider, providers, mbRepo, domRepo, mbSvc), nil
}

var identityCmd = &cobra.Command{
	Use:   "identity",
	Short: "Manage directory identities and multi-provider authentication",
}

var identityAuthCmd = &cobra.Command{
	Use:   "auth <username>",
	Short: "Authenticate an identity against the configured provider",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		username := args[0]
		var password string

		passStdin, _ := cmd.Flags().GetBool("password-stdin")
		passFlag, _ := cmd.Flags().GetString("password")

		if passStdin {
			scanner := bufio.NewScanner(os.Stdin)
			if scanner.Scan() {
				password = scanner.Text()
			}
		} else if passFlag != "" {
			password = passFlag
		} else {
			return fmt.Errorf("password must be supplied via --password or --password-stdin")
		}

		cfg, err := config.Load()
		if err != nil {
			return err
		}

		svc, err := initIdentityService(cfg)
		if err != nil {
			return err
		}

		id, err := svc.Authenticate(cmd.Context(), username, password)
		if err != nil {
			return fmt.Errorf("authentication failed: %w", err)
		}

		fmt.Printf("Authentication SUCCESS: %s (%s) [Provider: %s, Roles: %v]\n", id.DisplayName, id.Email, id.Provider, id.Roles)
		return nil
	},
}

var identityLookupCmd = &cobra.Command{
	Use:   "lookup <username>",
	Short: "Lookup identity attributes and groups in directory",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		username := args[0]
		cfg, err := config.Load()
		if err != nil {
			return err
		}

		svc, err := initIdentityService(cfg)
		if err != nil {
			return err
		}

		id, err := svc.Lookup(cmd.Context(), username)
		if err != nil {
			return err
		}

		fmt.Printf("Identity: %s\n", id.Email)
		fmt.Printf("Display Name: %s\n", id.DisplayName)
		fmt.Printf("Provider: %s\n", id.Provider)
		fmt.Printf("Status: %s\n", id.Status)
		if len(id.Roles) > 0 {
			fmt.Printf("Roles: %v\n", id.Roles)
		}
		if len(id.Groups) > 0 {
			fmt.Printf("Groups: %s\n", strings.Join(id.Groups, ", "))
		}
		return nil
	},
}

var identitySyncCmd = &cobra.Command{
	Use:   "sync",
	Short: "Synchronize directory identities into local mailboxes",
	RunE: func(cmd *cobra.Command, args []string) error {
		domName, _ := cmd.Flags().GetString("domain")
		autoCreate, _ := cmd.Flags().GetBool("auto-create")
		dryRun, _ := cmd.Flags().GetBool("dry-run")

		cfg, err := config.Load()
		if err != nil {
			return err
		}

		svc, err := initIdentityService(cfg)
		if err != nil {
			return err
		}

		report, err := svc.Sync(cmd.Context(), identity.SyncOptions{
			DomainName:        domName,
			AutoCreateMailbox: autoCreate,
			DryRun:            dryRun,
		})
		if err != nil {
			return err
		}

		fmt.Printf("Identity Synchronization Complete (%v)\n", report.Duration)
		fmt.Printf("Total Identities Discovered: %d\n", report.TotalIdentities)
		fmt.Printf("Mailboxes Created:           %d\n", report.Created)
		fmt.Printf("Mailboxes Updated:           %d\n", report.Updated)
		fmt.Printf("Mailboxes Suspended:         %d\n", report.Suspended)
		fmt.Printf("Skipped:                     %d\n", report.Skipped)
		if len(report.Errors) > 0 {
			fmt.Printf("Errors (%d):\n", len(report.Errors))
			for _, e := range report.Errors {
				fmt.Printf(" - %s\n", e)
			}
		}
		return nil
	},
}

func init() {
	identityAuthCmd.Flags().Bool("password-stdin", false, "Read password from standard input")
	identityAuthCmd.Flags().String("password", "", "User password")
	identityCmd.AddCommand(identityAuthCmd)
	identityCmd.AddCommand(identityLookupCmd)

	identitySyncCmd.Flags().String("domain", "", "Filter synchronization to specific domain")
	identitySyncCmd.Flags().Bool("auto-create", false, "Automatically provision new mailboxes for discovered identities")
	identitySyncCmd.Flags().Bool("dry-run", false, "Simulate sync without modifying database")
	identityCmd.AddCommand(identitySyncCmd)

	rootCmd.AddCommand(identityCmd)
}
