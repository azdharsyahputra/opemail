package dovecot

import (
	"context"
	"fmt"
	"strings"

	"github.com/azdharsyahputra/openmail/internal/mailbox"
)

// Authenticator defines the decoupled authentication interface.
type Authenticator interface {
	Authenticate(ctx context.Context, username, password string) error
}

type Service interface {
	Authenticator
	GetUserInfo(ctx context.Context, username string, vmailRoot string, uid, gid int) (*UserInfo, error)
	ApplyConfig(ctx context.Context, opts ConfigOptions) error
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

func (s *service) Authenticate(ctx context.Context, username, password string) error {
	username = strings.TrimSpace(strings.ToLower(username))
	if username == "" || password == "" {
		return ErrAuthenticationFailed
	}

	hash, err := s.repo.GetPasswordHash(ctx, username)
	if err != nil {
		// Return generic authentication failure without leaking user existence
		return ErrAuthenticationFailed
	}

	valid, err := mailbox.VerifyPassword(password, hash)
	if err != nil || !valid {
		return ErrAuthenticationFailed
	}

	return nil
}

func (s *service) GetUserInfo(ctx context.Context, username string, vmailRoot string, uid, gid int) (*UserInfo, error) {
	username = strings.TrimSpace(strings.ToLower(username))
	return s.repo.GetUserInfo(ctx, username, vmailRoot, uid, gid)
}

func (s *service) ApplyConfig(ctx context.Context, opts ConfigOptions) error {
	if err := WriteConfigsAtomically(opts); err != nil {
		return fmt.Errorf("failed to write dovecot configs: %w", err)
	}

	if err := s.provisioner.Validate(ctx); err != nil {
		return fmt.Errorf("dovecot config validation failed: %w", err)
	}

	status, err := s.provisioner.Status(ctx)
	if err == nil && status == "running" {
		return s.provisioner.Reload(ctx)
	}

	return nil
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
