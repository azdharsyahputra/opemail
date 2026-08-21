package postfix

import (
	"context"
	"fmt"
	"strings"
)

// MailTransport defines the decoupled transport validation interface.
type MailTransport interface {
	ValidateRecipient(ctx context.Context, email string) (bool, error)
}

type Service interface {
	MailTransport
	ApplyConfig(ctx context.Context, opts ConfigOptions) error
	LookupDomain(ctx context.Context, domainName string) (bool, error)
	LookupMailbox(ctx context.Context, email string) (bool, error)
	LookupAlias(ctx context.Context, sourceEmail string) ([]string, error)
	Reload(ctx context.Context) error
	GetProvisioner() Provisioner
	GetRepository() Repository
}

type service struct {
	repo        Repository
	provisioner Provisioner
}

func NewService(repo Repository, provisioner Provisioner) Service {
	return &service{
		repo:        repo,
		provisioner: provisioner,
	}
}

func (s *service) ValidateRecipient(ctx context.Context, email string) (bool, error) {
	email = strings.TrimSpace(strings.ToLower(email))
	parts := strings.Split(email, "@")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return false, ErrInvalidRecipient
	}

	domainName := parts[1]

	// 1. Check if domain is accepted for virtual delivery
	domainFound, err := s.repo.LookupVirtualDomain(ctx, domainName)
	if err != nil {
		return false, err
	}
	if !domainFound {
		return false, ErrDomainNotFound
	}

	// 2. Check if recipient matches a virtual alias
	aliases, err := s.repo.LookupVirtualAlias(ctx, email)
	if err == nil && len(aliases) > 0 {
		return true, nil
	}

	// 3. Check if recipient matches an active and ready mailbox
	mailboxFound, err := s.repo.LookupVirtualMailbox(ctx, email)
	if err != nil {
		return false, err
	}
	if !mailboxFound {
		return false, ErrMailboxNotFound
	}

	return true, nil
}

func (s *service) ApplyConfig(ctx context.Context, opts ConfigOptions) error {
	if err := WriteConfigsAtomically(opts); err != nil {
		return fmt.Errorf("failed to write postfix configs: %w", err)
	}

	if err := s.provisioner.Validate(ctx); err != nil {
		return fmt.Errorf("postfix config validation failed: %w", err)
	}

	status, err := s.provisioner.Status(ctx)
	if err == nil && status == "running" {
		return s.provisioner.Reload(ctx)
	}

	return nil
}

func (s *service) LookupDomain(ctx context.Context, domainName string) (bool, error) {
	return s.repo.LookupVirtualDomain(ctx, domainName)
}

func (s *service) LookupMailbox(ctx context.Context, email string) (bool, error) {
	return s.repo.LookupVirtualMailbox(ctx, email)
}

func (s *service) LookupAlias(ctx context.Context, sourceEmail string) ([]string, error) {
	return s.repo.LookupVirtualAlias(ctx, sourceEmail)
}

func (s *service) Reload(ctx context.Context) error {
	return s.provisioner.Reload(ctx)
}

func (s *service) GetProvisioner() Provisioner {
	return s.provisioner
}

func (s *service) GetRepository() Repository {
	return s.repo
}
