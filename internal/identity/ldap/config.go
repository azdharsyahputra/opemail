package ldap

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"time"
)

type Config struct {
	URL                string            `json:"url"` // e.g. "ldaps://ldap.example.com:636" or "ldap://127.0.0.1:389"
	BaseDN             string            `json:"base_dn"`
	UserBaseDN         string            `json:"user_base_dn"`
	UserFilter         string            `json:"user_filter"` // e.g. "(|(mail={username})(uid={username}))"
	GroupBaseDN        string            `json:"group_base_dn"`
	GroupFilter        string            `json:"group_filter"` // e.g. "(|(member={dn})(uniqueMember={dn}))"
	BindDN             string            `json:"bind_dn"`
	BindPassword       string            `json:"bind_password"`
	StartTLS           bool              `json:"start_tls"`
	InsecureSkipVerify bool              `json:"insecure_skip_verify"`
	CAFile             string            `json:"ca_file,omitempty"`
	ServerName         string            `json:"server_name,omitempty"`
	Timeout            time.Duration     `json:"timeout"`
	GroupRoleMapping   map[string]string `json:"group_role_mapping,omitempty"`
}

func DefaultConfig() Config {
	return Config{
		URL:         "ldaps://127.0.0.1:636",
		BaseDN:      "dc=example,dc=com",
		UserBaseDN:  "ou=people,dc=example,dc=com",
		UserFilter:  "(|(mail={username})(uid={username}))",
		GroupBaseDN: "ou=groups,dc=example,dc=com",
		GroupFilter: "(|(member={dn})(uniqueMember={dn}))",
		Timeout:     5 * time.Second,
		GroupRoleMapping: map[string]string{
			"mail-admins":    "admin",
			"mail-operators": "operator",
			"mail-auditors":  "auditor",
		},
	}
}

func (c *Config) BuildTLSConfig() (*tls.Config, error) {
	tlsConfig := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: c.InsecureSkipVerify,
		ServerName:         c.ServerName,
	}

	if c.CAFile != "" {
		caPEM, err := os.ReadFile(c.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read LDAP CA file %s: %w", c.CAFile, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("failed to parse CA certificate from %s", c.CAFile)
		}
		tlsConfig.RootCAs = pool
	}

	return tlsConfig, nil
}
