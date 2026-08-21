package identity

import "errors"

var (
	ErrIdentityNotFound       = errors.New("identity not found in directory")
	ErrAuthenticationFailed   = errors.New("authentication failed: invalid username or password")
	ErrAccountSuspended       = errors.New("account is suspended")
	ErrAccountDisabled        = errors.New("account is disabled")
	ErrAccountPending         = errors.New("account provisioning is pending")
	ErrInvalidCredentials     = errors.New("invalid credentials provided")
	ErrProviderUnavailable    = errors.New("identity directory provider is unreachable")
	ErrLDAPInjectionDetected  = errors.New("security error: potential LDAP injection payload detected")
	ErrPasswordChangeRejected = errors.New("password change rejected by identity provider policy")
)
