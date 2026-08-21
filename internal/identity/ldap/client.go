package ldap

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/azdharsyahputra/openmail/internal/identity"
	goldap "github.com/go-ldap/ldap/v3"
)


type Client interface {
	Search(ctx context.Context, baseDN, filter string, scope int, attributes []string) ([]*goldap.Entry, error)
	Bind(ctx context.Context, dn, password string) error
	AuthenticateUser(ctx context.Context, userDN, password string) error
	PasswordModify(ctx context.Context, userDN, oldPassword, newPassword string) error
	Close() error
}

type systemClient struct {
	cfg Config
}

func NewClient(cfg Config) Client {
	if cfg.Timeout == 0 {
		cfg.Timeout = 5 * time.Second
	}
	return &systemClient{cfg: cfg}
}

func (c *systemClient) dial(ctx context.Context) (*goldap.Conn, error) {
	tlsConfig, err := c.cfg.BuildTLSConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to build TLS config: %w", err)
	}

	conn, err := goldap.DialURL(c.cfg.URL, goldap.DialWithTLSConfig(tlsConfig))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", identity.ErrProviderUnavailable, err)
	}

	if c.cfg.StartTLS && !strings.HasPrefix(strings.ToLower(c.cfg.URL), "ldaps://") {
		if startTLSErr := conn.StartTLS(tlsConfig); startTLSErr != nil {
			conn.Close()
			return nil, fmt.Errorf("startTLS failed: %w", startTLSErr)
		}
	}

	conn.SetTimeout(c.cfg.Timeout)

	return conn, nil
}

func (c *systemClient) Search(ctx context.Context, baseDN, filter string, scope int, attributes []string) ([]*goldap.Entry, error) {
	conn, err := c.dial(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if c.cfg.BindDN != "" {
		if err := conn.Bind(c.cfg.BindDN, c.cfg.BindPassword); err != nil {
			return nil, fmt.Errorf("service bind failed: %w", err)
		}
	}

	if scope == 0 {
		scope = goldap.ScopeWholeSubtree
	}

	searchReq := goldap.NewSearchRequest(
		baseDN,
		scope,
		goldap.NeverDerefAliases,
		0,
		int(c.cfg.Timeout.Seconds()),
		false,
		filter,
		attributes,
		nil,
	)

	sr, err := conn.Search(searchReq)
	if err != nil {
		return nil, fmt.Errorf("ldap search failed: %w", err)
	}

	return sr.Entries, nil
}

func (c *systemClient) Bind(ctx context.Context, dn, password string) error {
	conn, err := c.dial(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()

	if err := conn.Bind(dn, password); err != nil {
		if goldap.IsErrorWithCode(err, goldap.LDAPResultInvalidCredentials) {
			return identity.ErrAuthenticationFailed
		}
		return fmt.Errorf("bind error: %w", err)
	}
	return nil
}

func (c *systemClient) AuthenticateUser(ctx context.Context, userDN, password string) error {
	return c.Bind(ctx, userDN, password)
}

func (c *systemClient) PasswordModify(ctx context.Context, userDN, oldPassword, newPassword string) error {
	conn, err := c.dial(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()

	if c.cfg.BindDN != "" {
		if err := conn.Bind(c.cfg.BindDN, c.cfg.BindPassword); err != nil {
			return fmt.Errorf("service bind failed: %w", err)
		}
	}

	pwdModifyReq := goldap.NewPasswordModifyRequest(userDN, oldPassword, newPassword)
	_, err = conn.PasswordModify(pwdModifyReq)
	if err != nil {
		return fmt.Errorf("failed to modify password: %w", err)
	}
	return nil
}

func (c *systemClient) Close() error {
	return nil
}
