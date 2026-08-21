package cli

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/azdharsyahputra/openmail/internal/api"
	"github.com/azdharsyahputra/openmail/internal/api/handler"
	"github.com/azdharsyahputra/openmail/internal/api/token"
	"github.com/azdharsyahputra/openmail/internal/audit"
	"github.com/azdharsyahputra/openmail/internal/config"
	"github.com/azdharsyahputra/openmail/internal/database"
	"github.com/azdharsyahputra/openmail/internal/dkim"
	"github.com/azdharsyahputra/openmail/internal/domain"
	"github.com/azdharsyahputra/openmail/internal/identity"
	"github.com/azdharsyahputra/openmail/internal/identity/ldap"
	"github.com/azdharsyahputra/openmail/internal/identity/local"
	"github.com/azdharsyahputra/openmail/internal/mailbox"
	"github.com/azdharsyahputra/openmail/internal/metrics"
	"github.com/azdharsyahputra/openmail/internal/provisioning"
	"github.com/azdharsyahputra/openmail/internal/queue"
	"github.com/azdharsyahputra/openmail/internal/quota"
	openmailtls "github.com/azdharsyahputra/openmail/internal/tls"
	"github.com/spf13/cobra"
)


var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Start the MailOpen REST API Control Plane HTTP server",
	RunE: func(cmd *cobra.Command, args []string) error {
		addr, _ := cmd.Flags().GetString("addr")
		cfg, err := config.Load()
		if err != nil {
			return err
		}

		db, err := database.NewPostgresDB(cfg.DatabaseURL)
		if err != nil {
			return fmt.Errorf("database connection failed: %w", err)
		}
		defer db.Close()

		logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

		// Repositories
		domRepo := domain.NewPostgresRepository(db)
		mbRepo := mailbox.NewPostgresRepository(db)
		aliasRepo := mailbox.NewAliasRepository(db)
		tokenRepo := token.NewPostgresRepository(db)
		auditRepo := audit.NewPostgresRepository(db)
		dkimRepo := dkim.NewPostgresRepository(db)

		// Services
		prov, _ := provisioning.NewFilesystemProvisioner(cfg.VmailDir, cfg.VmailUID, cfg.VmailGID)
		mbSvc := mailbox.NewService(mbRepo, domRepo, prov)
		domSvc := domain.NewService(domRepo)
		tokenMgr := token.NewManager(tokenRepo)
		auditSvc := audit.NewService(auditRepo)
		qSvc := queue.NewService(queue.NewSystemDriver("mailopen_postfix"))
		quotaSvc := quota.NewService(mbRepo, prov)

		keystore := dkim.NewFilesystemKeystore(cfg.DKIMBaseDir)
		dkimSvc := dkim.NewService(dkimRepo, domRepo, keystore)
		tlsProv := openmailtls.NewFilesystemProvider(cfg.TLSBaseDir)
		tlsSvc := openmailtls.NewService(tlsProv)

		// Identity Service
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
		identSvc := identity.NewService(cfg.IdentityProvider, providers, mbRepo, domRepo, mbSvc)

		healthHandler := handler.NewHealthHandler(db, qSvc, cfg.VmailDir, cfg.TLSBaseDir, cfg.DKIMBaseDir)

		router := api.NewRouter(api.RouterDependencies{
			Logger:          logger,
			TokenManager:    tokenMgr,
			IdentityService: identSvc,
			DomainService:   domSvc,
			MailboxService:  mbSvc,
			QuotaService:    quotaSvc,
			AliasRepo:       aliasRepo,
			MailboxRepo:     mbRepo,
			DomainRepo:      domRepo,
			DKIMService:     dkimSvc,
			TLSService:      tlsSvc,
			QueueService:    qSvc,
			AuditService:    auditSvc,
			HealthHandler:   healthHandler,
			MetricsRegistry: metrics.DefaultRegistry,
		})


		srv := api.NewServer(addr, router)
		fmt.Printf("MailOpen REST API Control Plane listening on %s\n", addr)
		return srv.Start()
	},
}

func init() {
	serverCmd.Flags().String("addr", ":8080", "HTTP server listen address")
	rootCmd.AddCommand(serverCmd)
}
