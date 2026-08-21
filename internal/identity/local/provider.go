package local

import (
	"context"
	"fmt"
	"strings"

	"github.com/azdharsyahputra/openmail/internal/identity"
	"github.com/azdharsyahputra/openmail/internal/mailbox"
)



type Provider struct {
	mailboxRepo mailbox.Repository
}

func NewProvider(mbRepo mailbox.Repository) *Provider {
	return &Provider{mailboxRepo: mbRepo}
}

func (p *Provider) Name() string {
	return "local"
}

func (p *Provider) Authenticate(ctx context.Context, username, password string) (*identity.Identity, error) {
	email := identity.CanonicalizeUsername(username)
	if email == "" || password == "" {
		return nil, identity.ErrInvalidCredentials
	}

	mb, err := p.mailboxRepo.GetByEmail(ctx, email)
	if err != nil {
		// Constant-time dummy hash verification to mitigate timing attacks
		dummyHash := "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHRzb21lc2FsdA$q8Y9X2eYqV3HwJpZ5K3r7Z"
		_, _ = mailbox.VerifyPassword(password, dummyHash)
		return nil, identity.ErrAuthenticationFailed
	}

	// Gate status
	if mb.Status == "suspended" {
		return nil, identity.ErrAccountSuspended
	}
	if mb.Status == "disabled" {
		return nil, identity.ErrAccountDisabled
	}
	if mb.ProvisioningStatus != mailbox.ProvisioningReady && mb.ProvisioningStatus != "active" {
		return nil, identity.ErrAccountPending
	}

	valid, err := mailbox.VerifyPassword(password, mb.PasswordHash)
	if err != nil || !valid {
		return nil, identity.ErrAuthenticationFailed
	}

	roles := []identity.Role{identity.RoleUser}
	if strings.HasPrefix(strings.ToLower(mb.Email), "admin@") || strings.HasPrefix(strings.ToLower(mb.Email), "root@") {
		roles = []identity.Role{identity.RoleAdmin}
	}

	id := &identity.Identity{
		ID:        mb.ID.String(),
		Username:  mb.Email,
		Email:     mb.Email,
		Status:    identity.StatusActive,
		Provider:  "local",
		Roles:     roles,
		CreatedAt: mb.CreatedAt,
		UpdatedAt: mb.UpdatedAt,
	}
	return id, nil
}

func (p *Provider) Lookup(ctx context.Context, username string) (*identity.Identity, error) {
	email := identity.CanonicalizeUsername(username)
	mb, err := p.mailboxRepo.GetByEmail(ctx, email)
	if err != nil {
		return nil, identity.ErrIdentityNotFound
	}

	status := identity.StatusActive
	if mb.Status == "suspended" {
		status = identity.StatusSuspended
	} else if mb.Status == "disabled" {
		status = identity.StatusDisabled
	}

	roles := []identity.Role{identity.RoleUser}
	if strings.HasPrefix(strings.ToLower(mb.Email), "admin@") || strings.HasPrefix(strings.ToLower(mb.Email), "root@") {
		roles = []identity.Role{identity.RoleAdmin}
	}

	return &identity.Identity{
		ID:        mb.ID.String(),
		Username:  mb.Email,
		Email:     mb.Email,
		Status:    status,
		Provider:  "local",
		Roles:     roles,
		CreatedAt: mb.CreatedAt,
		UpdatedAt: mb.UpdatedAt,
	}, nil

}

func (p *Provider) Groups(ctx context.Context, username string) ([]identity.Group, error) {
	// Local mailboxes are mapped to basic user group
	return []identity.Group{
		{
			ID:   "local-users",
			Name: "users",
		},
	}, nil
}

func (p *Provider) SetPassword(ctx context.Context, username, newPassword string) error {
	email := identity.CanonicalizeUsername(username)
	if len(newPassword) < 8 {
		return fmt.Errorf("password must be at least 8 characters long")
	}

	mb, err := p.mailboxRepo.GetByEmail(ctx, email)
	if err != nil {
		return identity.ErrIdentityNotFound
	}

	hashedPassword, err := mailbox.HashPassword(newPassword, mailbox.DefaultArgon2Params)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	return p.mailboxRepo.UpdatePasswordHash(ctx, mb.ID, hashedPassword)
}
