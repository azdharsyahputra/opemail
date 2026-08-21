package dovecot

import (
	"context"
)

type Repository interface {
	GetPasswordHash(ctx context.Context, username string) (string, error)
	GetUserInfo(ctx context.Context, username string, vmailRoot string, uid, gid int) (*UserInfo, error)
}
