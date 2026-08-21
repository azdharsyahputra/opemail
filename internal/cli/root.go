package cli

import (
	"database/sql"
	"fmt"
	"os"

	"github.com/azdharsyahputra/openmail/internal/config"
	"github.com/azdharsyahputra/openmail/internal/database"
	"github.com/azdharsyahputra/openmail/internal/domain"
	"github.com/azdharsyahputra/openmail/internal/dovecot"
	"github.com/azdharsyahputra/openmail/internal/mailbox"
	"github.com/azdharsyahputra/openmail/internal/message"
	"github.com/azdharsyahputra/openmail/internal/postfix"
	"github.com/azdharsyahputra/openmail/internal/provisioning"
	"github.com/azdharsyahputra/openmail/internal/storage"
	"github.com/spf13/cobra"
)

var (
	db             *sql.DB
	domainService  domain.Service
	mailboxService mailbox.Service
	blobStore      storage.BlobStore
	messageRepo    message.Repository
	messageService message.Service
	postfixRepo    postfix.Repository
	postfixService postfix.Service
	dovecotRepo    dovecot.Repository
	dovecotService dovecot.Service
)

var rootCmd = &cobra.Command{
	Use:   "mailopen",
	Short: "mailopen is a mail server management CLI",
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// Skip DB connection for help or simple commands if needed
		if cmd.Name() == "help" {
			return nil
		}

		cfg, err := config.Load()
		if err != nil {
			return fmt.Errorf("failed to load config: %w", err)
		}

		databaseConn, err := database.NewPostgresDB(cfg.DatabaseURL)
		if err != nil {
			return fmt.Errorf("failed to connect to database (%s): %w", cfg.DatabaseURL, err)
		}
		db = databaseConn

		bs, err := storage.NewFilesystemBlobStore(cfg.StoragePath)
		if err != nil {
			return fmt.Errorf("failed to initialize blob store (%s): %w", cfg.StoragePath, err)
		}
		blobStore = bs

		prov, err := provisioning.NewFilesystemProvisioner(cfg.VmailRoot, cfg.VmailUID, cfg.VmailGID)
		if err != nil {
			return fmt.Errorf("failed to initialize vmail provisioner (%s): %w", cfg.VmailRoot, err)
		}

		domainRepo := domain.NewPostgresRepository(db)
		mailboxRepo := mailbox.NewPostgresRepository(db)
		messageRepo = message.NewPostgresRepository(db)
		postfixRepo = postfix.NewPostgresRepository(db)
		dovecotRepo = dovecot.NewPostgresRepository(db)

		postfixProv := postfix.NewSystemProvisioner(cfg.PostfixConfigDir)
		postfixService = postfix.NewService(postfixRepo, postfixProv)

		dovecotProv := dovecot.NewSystemProvisioner(cfg.DovecotConfigDir)
		dovecotService = dovecot.NewService(dovecotRepo, dovecotProv)

		domainService = domain.NewService(domainRepo)
		mailboxService = mailbox.NewService(mailboxRepo, domainRepo, prov)
		messageService = message.NewService(messageRepo, mailboxRepo, blobStore)

		return nil
	},
	PersistentPostRunE: func(cmd *cobra.Command, args []string) error {
		if db != nil {
			return db.Close()
		}
		return nil
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.AddCommand(domainCmd)
	rootCmd.AddCommand(mailboxCmd)
	rootCmd.AddCommand(messageCmd)
	rootCmd.AddCommand(postfixCmd)
	rootCmd.AddCommand(dovecotCmd)
	rootCmd.AddCommand(storageCmd)
	rootCmd.AddCommand(migrateCmd)
}
