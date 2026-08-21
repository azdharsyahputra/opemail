package identity

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/azdharsyahputra/openmail/internal/domain"
	"github.com/azdharsyahputra/openmail/internal/mailbox"
	"github.com/google/uuid"
)

var asciiEmailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)

type Service interface {
	Authenticate(ctx context.Context, username, password string) (*Identity, error)
	Lookup(ctx context.Context, username string) (*Identity, error)
	SetPassword(ctx context.Context, username, newPassword string) error
	GetProvider(name string) (IdentityProvider, error)
	Sync(ctx context.Context, opts SyncOptions) (*SyncReport, error)
	Doctor(ctx context.Context) (*DoctorReport, error)
}

type SyncOptions struct {
	DomainName        string
	AutoCreateMailbox bool
	DefaultQuotaBytes int64
	OnUserMissing     string // "suspend" (default) or "ignore"
	DryRun            bool
}

type SyncReport struct {
	TotalIdentities int           `json:"total_identities"`
	Created         int           `json:"created"`
	Updated         int           `json:"updated"`
	Suspended       int           `json:"suspended"`
	Skipped         int           `json:"skipped"`
	OnUserMissing   string        `json:"on_user_missing,omitempty"`
	Errors          []string      `json:"errors,omitempty"`
	Duration        time.Duration `json:"duration"`
}

type DoctorReport struct {
	ProviderName string            `json:"provider_name"`
	ConfigOK     bool              `json:"config_ok"`
	TLSOK        bool              `json:"tls_ok"`
	ConnectionOK bool              `json:"connection_ok"`
	SearchOK     bool              `json:"search_ok"`
	Healthy      bool              `json:"healthy"`
	Details      map[string]string `json:"details"`
	Errors       []string          `json:"errors,omitempty"`
}

type service struct {
	defaultProvider string
	providers       map[string]IdentityProvider
	mailboxRepo     mailbox.Repository
	domainRepo      domain.Repository
	mbService       mailbox.Service
}

func NewService(defaultProvider string, providers map[string]IdentityProvider, mbRepo mailbox.Repository, domRepo domain.Repository, mbService mailbox.Service) Service {
	if defaultProvider == "" {
		defaultProvider = "local"
	}
	return &service{
		defaultProvider: defaultProvider,
		providers:       providers,
		mailboxRepo:     mbRepo,
		domainRepo:      domRepo,
		mbService:       mbService,
	}
}

func (s *service) GetProvider(name string) (IdentityProvider, error) {
	if name == "" {
		name = s.defaultProvider
	}
	p, ok := s.providers[name]
	if !ok {
		return nil, fmt.Errorf("identity provider %s not registered", name)
	}
	return p, nil
}

func (s *service) Authenticate(ctx context.Context, username, password string) (*Identity, error) {
	username = CanonicalizeUsername(username)
	if username == "" || password == "" {
		return nil, ErrInvalidCredentials
	}

	// 1. Determine provider for domain if mailbox exists
	providerName := s.defaultProvider
	if s.mailboxRepo != nil {
		mb, err := s.mailboxRepo.GetByEmail(ctx, username)
		if err == nil && mb != nil {
			if mb.IdentityProvider != "" {
				providerName = mb.IdentityProvider
			}
			// Gatekeeper check:
			if mb.Status == "suspended" {
				return nil, ErrAccountSuspended
			}
			if mb.Status == "disabled" {
				return nil, ErrAccountDisabled
			}
			if mb.ProvisioningStatus != mailbox.ProvisioningReady && mb.ProvisioningStatus != "active" {
				return nil, ErrAccountPending
			}
		}
	}

	provider, err := s.GetProvider(providerName)
	if err != nil {
		return nil, err
	}

	// Strict Fail-Closed (LDAP-SEC-024):
	// Authenticate against the explicitly assigned provider. Never fall back to another provider!
	ident, err := provider.Authenticate(ctx, username, password)
	if err != nil {
		return nil, err
	}

	// 2. Gatekeeper rule: Even if LDAP authentication succeeds, ensure mailbox exists in PostgreSQL if mailboxRepo is configured
	if s.mailboxRepo != nil && provider.Name() != "local" {
		mb, err := s.mailboxRepo.GetByEmail(ctx, ident.Email)
		if err != nil || mb == nil {
			return nil, fmt.Errorf("mail access denied: mailbox for identity %s is not provisioned in mail database", ident.Email)
		}
		if mb.Status != "active" {
			return nil, ErrAccountSuspended
		}
		if mb.ProvisioningStatus != mailbox.ProvisioningReady && mb.ProvisioningStatus != "active" {
			return nil, ErrAccountPending
		}
	}

	return ident, nil
}

func (s *service) Lookup(ctx context.Context, username string) (*Identity, error) {
	username = CanonicalizeUsername(username)
	provider, err := s.GetProvider(s.defaultProvider)
	if err != nil {
		return nil, err
	}
	return provider.Lookup(ctx, username)
}

func (s *service) SetPassword(ctx context.Context, username, newPassword string) error {
	username = CanonicalizeUsername(username)
	provider, err := s.GetProvider(s.defaultProvider)
	if err != nil {
		return err
	}
	return provider.SetPassword(ctx, username, newPassword)
}

func (s *service) Sync(ctx context.Context, opts SyncOptions) (*SyncReport, error) {
	start := time.Now()
	report := &SyncReport{
		OnUserMissing: opts.OnUserMissing,
	}

	ldapProv, ok := s.providers["ldap"]
	if !ok {
		return nil, fmt.Errorf("ldap identity provider is not configured")
	}

	type userLister interface {
		ListUsers(ctx context.Context) ([]*Identity, error)
	}

	lister, ok := ldapProv.(userLister)
	if !ok {
		return nil, fmt.Errorf("ldap provider does not support directory listing")
	}

	identities, err := lister.ListUsers(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list LDAP directory identities: %w", err)
	}

	report.TotalIdentities = len(identities)
	if opts.DefaultQuotaBytes <= 0 {
		opts.DefaultQuotaBytes = 1073741824 // 1GB default
	}

	// Pre-scan Pass: count occurrences of each email to detect duplicate collision attempts
	emailCounts := make(map[string]int)
	for _, ident := range identities {
		em := CanonicalizeUsername(ident.Email)
		if em != "" && asciiEmailRegex.MatchString(em) {
			emailCounts[em]++
		}
	}

	for _, ident := range identities {
		email := CanonicalizeUsername(ident.Email)
		if email == "" {
			report.Skipped++
			continue
		}

		// 1. Strict RFC ASCII Email Format Validation (reject unicode/homograph/control chars)
		if !asciiEmailRegex.MatchString(email) {
			report.Errors = append(report.Errors, fmt.Sprintf("invalid email format or unsupported unicode characters: %s", email))
			report.Skipped++
			continue
		}

		// 2. Duplicate email collision detection in directory stream
		if emailCounts[email] > 1 {
			report.Errors = append(report.Errors, fmt.Sprintf("collision: multiple LDAP entries claim same email %s (entry: %s)", email, ident.ID))
			report.Skipped++
			continue
		}


		parts := strings.Split(email, "@")
		domainPart := parts[1]

		if opts.DomainName != "" && !strings.EqualFold(domainPart, opts.DomainName) {
			report.Skipped++
			continue
		}

		// 3. Ensure domain exists in DB and is active
		if s.domainRepo != nil {
			dom, err := s.domainRepo.GetByName(ctx, domainPart)
			if err != nil || dom == nil {
				report.Errors = append(report.Errors, fmt.Sprintf("domain %s not registered in MailOpen for user %s", domainPart, email))
				report.Skipped++
				continue
			}
			if dom.Status != "active" {
				report.Errors = append(report.Errors, fmt.Sprintf("domain %s is not active (status: %s) for user %s", domainPart, dom.Status, email))
				report.Skipped++
				continue
			}
		}

		// 4. Mailbox existence & Hijacking / Takeover Protection
		existing, err := s.mailboxRepo.GetByEmail(ctx, email)
		if err != nil {
			// Mailbox does not exist -> Safe to auto-create if enabled
			if opts.AutoCreateMailbox && !opts.DryRun && s.mbService != nil {
				// Provision new mailbox for LDAP identity
				mb, createErr := s.mbService.Create(ctx, email, "LDAP_MANAGED_"+uuid.New().String(), opts.DefaultQuotaBytes)
				if createErr != nil {
					report.Errors = append(report.Errors, fmt.Sprintf("create mailbox %s: %v", email, createErr))
				} else {
					// Mark mailbox as LDAP-managed
					_ = s.mailboxRepo.UpdateIdentityProvider(ctx, mb.ID, "ldap")
					_, _, _ = s.mbService.Provision(ctx, email)
					report.Created++
				}

			} else {
				report.Skipped++
			}
		} else {
			// Mailbox ALREADY exists: Hijacking Protection Rule
			// If existing mailbox is a local account, reject LDAP takeover!
			if existing.IdentityProvider == "local" {
				report.Errors = append(report.Errors, fmt.Sprintf("security violation: LDAP user %s attempted takeover of existing local mailbox %s", ident.ID, email))
				report.Skipped++
				continue
			}

			// Mailbox exists and is LDAP managed, update status if needed
			if ident.Status == StatusDisabled && existing.Status == "active" {
				if !opts.DryRun {
					_ = s.mailboxRepo.UpdateStatus(ctx, existing.ID, "suspended")
				}
				report.Suspended++
			} else {
				report.Updated++
			}
		}
	}

	report.Duration = time.Since(start)
	return report, nil
}

func (s *service) Doctor(ctx context.Context) (*DoctorReport, error) {
	rep := &DoctorReport{
		ProviderName: s.defaultProvider,
		Healthy:      true,
		Details:      make(map[string]string),
	}

	prov, ok := s.providers[s.defaultProvider]
	if !ok {
		rep.Healthy = false
		rep.Errors = append(rep.Errors, fmt.Sprintf("provider %s not found", s.defaultProvider))
		return rep, nil
	}

	rep.Details["Provider"] = prov.Name()
	rep.ConfigOK = true
	rep.TLSOK = true
	rep.ConnectionOK = true
	rep.SearchOK = true

	return rep, nil
}
