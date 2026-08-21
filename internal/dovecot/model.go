package dovecot

import "errors"

var (
	ErrAuthenticationFailed = errors.New("authentication failed")
	ErrUserNotFound         = errors.New("user not found or inactive")
	ErrDovecotCheckFail     = errors.New("dovecot configuration validation check failed")
)

type UserInfo struct {
	Username           string `json:"username"`
	Email              string `json:"email"`
	Domain             string `json:"domain"`
	Status             string `json:"status"`
	ProvisioningStatus string `json:"provisioning_status"`
	UID                int    `json:"uid"`
	GID                int    `json:"gid"`
	Home               string `json:"home"`
}

type AuthResult struct {
	Username      string `json:"username"`
	Authenticated bool   `json:"authenticated"`
}
