package postfix

import (
	"context"
)

type Repository interface {
	LookupVirtualDomain(ctx context.Context, domainName string) (bool, error)
	LookupVirtualMailbox(ctx context.Context, email string) (bool, error)
	LookupVirtualAlias(ctx context.Context, sourceEmail string) ([]string, error)
}
