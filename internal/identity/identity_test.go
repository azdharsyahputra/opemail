package identity_test

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/azdharsyahputra/openmail/internal/config"
	"github.com/azdharsyahputra/openmail/internal/database"
	"github.com/azdharsyahputra/openmail/internal/domain"
	"github.com/azdharsyahputra/openmail/internal/identity"
	"github.com/azdharsyahputra/openmail/internal/identity/ldap"
	"github.com/azdharsyahputra/openmail/internal/identity/local"
	"github.com/azdharsyahputra/openmail/internal/mailbox"
	"github.com/azdharsyahputra/openmail/internal/provisioning"
	goldap "github.com/go-ldap/ldap/v3"
)

func getTestDB(t *testing.T) *sql.DB {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		cfg, err := config.Load()
		if err == nil && cfg.DatabaseURL != "" {
			dbURL = cfg.DatabaseURL
		} else {
			dbURL = "postgres://mailopen:mailopen@localhost:5433/mailopen?sslmode=disable"
		}
	}
	db, err := database.NewPostgresDB(dbURL)
	if err != nil {
		t.Skipf("Skipping test: PostgreSQL unavailable (%v)", err)
		return nil
	}
	if err := database.RunMigrationsUp(db); err != nil {
		t.Fatalf("failed to run migrations: %v", err)
	}
	return db
}

type mockSyncLDAPClient struct {
	entries []*goldap.Entry
}

func (m *mockSyncLDAPClient) Search(ctx context.Context, baseDN, filter string, scope int, attributes []string) ([]*goldap.Entry, error) {
	return m.entries, nil
}

func (m *mockSyncLDAPClient) Bind(ctx context.Context, dn, password string) error {
	return nil
}

func (m *mockSyncLDAPClient) AuthenticateUser(ctx context.Context, userDN, password string) error {
	if password == "ValidSecretPass123!" {
		return nil
	}
	return identity.ErrAuthenticationFailed
}

func (m *mockSyncLDAPClient) PasswordModify(ctx context.Context, userDN, oldPassword, newPassword string) error {
	return nil
}

func (m *mockSyncLDAPClient) Close() error {
	return nil
}

func TestIdentityService_LocalAndGatekeeper(t *testing.T) {
	db := getTestDB(t)
	if db == nil {
		return
	}
	defer db.Close()

	ctx := context.Background()
	domRepo := domain.NewPostgresRepository(db)
	mbRepo := mailbox.NewPostgresRepository(db)
	tempVmail := t.TempDir()
	prov, _ := provisioning.NewFilesystemProvisioner(tempVmail, os.Getuid(), os.Getgid())
	domSvc := domain.NewService(domRepo)
	mbSvc := mailbox.NewService(mbRepo, domRepo, prov)

	testDom := fmt.Sprintf("ident-svc-%d.com", time.Now().UnixNano())
	_, _ = domSvc.Create(ctx, testDom)
	defer domSvc.Delete(ctx, testDom)

	localProv := local.NewProvider(mbRepo)
	mockClient := &mockSyncLDAPClient{
		entries: []*goldap.Entry{
			{
				DN: "uid=ldapuser,ou=people,dc=example,dc=com",
				Attributes: []*goldap.EntryAttribute{
					{Name: "uid", Values: []string{"ldapuser"}},
					{Name: "mail", Values: []string{"ldapuser@" + testDom}},
					{Name: "cn", Values: []string{"LDAP User"}},
				},
			},
		},
	}
	ldapProv := ldap.NewProvider(ldap.DefaultConfig(), mockClient)

	providers := map[string]identity.IdentityProvider{
		"local": localProv,
		"ldap":  ldapProv,
	}

	svc := identity.NewService("local", providers, mbRepo, domRepo, mbSvc)

	t.Run("Local identity authentication lifecycle", func(t *testing.T) {
		userEmail := "localuser@" + testDom
		pass := "StrongSecretPass123!"
		mb, err := mbSvc.Create(ctx, userEmail, pass, 1073741824)
		if err != nil {
			t.Fatalf("create mailbox failed: %v", err)
		}
		_, _, _ = mbSvc.Provision(ctx, userEmail)

		// 1. Success
		id, err := svc.Authenticate(ctx, userEmail, pass)
		if err != nil || id.Email != userEmail {
			t.Fatalf("local auth failed: %v", err)
		}

		// 2. Suspended
		_ = mbSvc.Suspend(ctx, mb.ID)
		_, err = svc.Authenticate(ctx, userEmail, pass)
		if err != identity.ErrAccountSuspended {
			t.Errorf("expected ErrAccountSuspended, got: %v", err)
		}

		// 3. Resumed
		_ = mbSvc.Resume(ctx, mb.ID)
		_, err = svc.Authenticate(ctx, userEmail, pass)
		if err != nil {
			t.Errorf("resumed auth failed: %v", err)
		}

		_ = mbSvc.Delete(ctx, userEmail)
	})

	t.Run("LDAP Gatekeeper: Unprovisioned LDAP user blocked from mail access", func(t *testing.T) {
		ldapSvc := identity.NewService("ldap", providers, mbRepo, domRepo, mbSvc)
		// ldapuser@testDom is NOT in PostgreSQL yet
		_, err := ldapSvc.Authenticate(ctx, "ldapuser@"+testDom, "ValidSecretPass123!")
		if err == nil {
			t.Errorf("expected unprovisioned LDAP user to be blocked from mail access")
		}
	})

	t.Run("LDAP Sync: Discovers and provisions mailboxes", func(t *testing.T) {
		ldapSvc := identity.NewService("ldap", providers, mbRepo, domRepo, mbSvc)
		syncReport, err := ldapSvc.Sync(ctx, identity.SyncOptions{
			DomainName:        testDom,
			AutoCreateMailbox: true,
		})
		if err != nil {
			t.Fatalf("ldap sync failed: %v", err)
		}

		if syncReport.Created != 1 {
			t.Errorf("expected 1 mailbox created by sync, got: %d", syncReport.Created)
		}

		// Now authenticate through LDAP service -> PASS
		id, err := ldapSvc.Authenticate(ctx, "ldapuser@"+testDom, "ValidSecretPass123!")
		if err != nil || id == nil {
			t.Errorf("authenticated through synced LDAP user failed: %v", err)
		}
	})
}
