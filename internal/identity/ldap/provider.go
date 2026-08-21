package ldap

import (
	"context"
	"fmt"
	"strings"

	"github.com/azdharsyahputra/openmail/internal/identity"
	goldap "github.com/go-ldap/ldap/v3"
)



type Provider struct {
	cfg    Config
	client Client
	mapper *Mapper
}

func NewProvider(cfg Config, client Client) *Provider {
	if client == nil {
		client = NewClient(cfg)
	}
	mapper := NewMapper(cfg.GroupRoleMapping)
	return &Provider{
		cfg:    cfg,
		client: client,
		mapper: mapper,
	}
}

func (p *Provider) Name() string {
	return "ldap"
}

func (p *Provider) Authenticate(ctx context.Context, username, password string) (*identity.Identity, error) {
	username = identity.CanonicalizeUsername(username)
	if username == "" || password == "" {
		return nil, identity.ErrInvalidCredentials
	}

	// 1. Search user DN using service bind
	filter, err := BuildUserFilter(p.cfg.UserFilter, username)

	if err != nil {
		return nil, err
	}

	attrs := []string{"uid", "sAMAccountName", "mail", "userPrincipalName", "cn", "displayName", "givenName", "sn", "nsAccountLock", "accountStatus", "memberOf"}
	entries, err := p.client.Search(ctx, p.cfg.UserBaseDN, filter, goldap.ScopeWholeSubtree, attrs)
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, identity.ErrAuthenticationFailed
	}
	if len(entries) > 1 {
		return nil, fmt.Errorf("ambiguous identity: multiple LDAP entries matched filter %s", filter)
	}

	userEntry := entries[0]
	userDN := userEntry.DN

	// Subtree Containment Check (LDAP-SEC-017 & LDAP-SEC-018):
	// Prevent base DN escape by verifying user DN is strictly subordinate to UserBaseDN
	if !isSubordinateDN(userDN, p.cfg.UserBaseDN) {
		return nil, fmt.Errorf("security violation: LDAP entry DN %q is outside configured UserBaseDN %q", userDN, p.cfg.UserBaseDN)
	}

	// 2. Perform direct user bind with user's password
	if err := p.client.AuthenticateUser(ctx, userDN, password); err != nil {
		return nil, identity.ErrAuthenticationFailed
	}

	// 3. Map identity & enforce active status
	ident := p.mapper.EntryToIdentity(userEntry)
	if ident == nil || ident.Username == "" || ident.Email == "" {
		return nil, identity.ErrAuthenticationFailed
	}
	if ident.Status == identity.StatusDisabled {
		return nil, identity.ErrAccountDisabled
	}
	if ident.Status == identity.StatusSuspended {
		return nil, identity.ErrAccountSuspended
	}

	return ident, nil
}

func (p *Provider) Lookup(ctx context.Context, username string) (*identity.Identity, error) {
	username = identity.CanonicalizeUsername(username)
	if username == "" {
		return nil, identity.ErrInvalidCredentials
	}

	filter, err := BuildUserFilter(p.cfg.UserFilter, username)
	if err != nil {
		return nil, err
	}

	attrs := []string{"uid", "sAMAccountName", "mail", "userPrincipalName", "cn", "displayName", "givenName", "sn", "nsAccountLock", "accountStatus", "memberOf"}
	entries, err := p.client.Search(ctx, p.cfg.UserBaseDN, filter, goldap.ScopeWholeSubtree, attrs)
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, identity.ErrIdentityNotFound
	}

	userEntry := entries[0]
	if !isSubordinateDN(userEntry.DN, p.cfg.UserBaseDN) {
		return nil, fmt.Errorf("security violation: LDAP entry DN %q is outside configured UserBaseDN %q", userEntry.DN, p.cfg.UserBaseDN)
	}

	ident := p.mapper.EntryToIdentity(userEntry)
	if ident == nil {
		return nil, identity.ErrIdentityNotFound
	}
	return ident, nil
}

func isSubordinateDN(dn, baseDN string) bool {
	if baseDN == "" {
		return true
	}
	normDN := strings.ToLower(strings.ReplaceAll(dn, " ", ""))
	normBase := strings.ToLower(strings.ReplaceAll(baseDN, " ", ""))
	return strings.HasSuffix(normDN, normBase)
}

func (p *Provider) SetPassword(ctx context.Context, username, newPassword string) error {

	user, err := p.Lookup(ctx, username)
	if err != nil {
		return err
	}

	userDN := user.Attributes["dn"]
	return p.client.PasswordModify(ctx, userDN, "", newPassword)
}

func (p *Provider) ListUsers(ctx context.Context) ([]*identity.Identity, error) {
	attrs := []string{"uid", "sAMAccountName", "mail", "userPrincipalName", "cn", "displayName", "givenName", "sn", "nsAccountLock", "accountStatus", "memberOf"}
	entries, err := p.client.Search(ctx, p.cfg.UserBaseDN, "(|(objectClass=person)(objectClass=inetOrgPerson)(objectClass=user))", goldap.ScopeWholeSubtree, attrs)
	if err != nil {
		return nil, fmt.Errorf("ldap list users failed: %w", err)
	}

	var identities []*identity.Identity
	for _, entry := range entries {
		ident := p.mapper.EntryToIdentity(entry)
		if ident != nil && ident.Email != "" {
			identities = append(identities, ident)
		}
	}
	return identities, nil
}
