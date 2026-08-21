package identity

import "context"

type IdentityProvider interface {
	Name() string
	Authenticate(ctx context.Context, username, password string) (*Identity, error)
	Lookup(ctx context.Context, username string) (*Identity, error)
	Groups(ctx context.Context, username string) ([]Group, error)
	SetPassword(ctx context.Context, username, newPassword string) error
}
