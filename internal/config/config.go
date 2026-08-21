package config

import (
	"os"
	"strconv"

	"github.com/joho/godotenv"
)

type Config struct {
	DatabaseURL       string
	StoragePath       string
	VmailRoot         string
	VmailUID          int
	VmailGID          int
	PostfixConfigDir  string
	PostfixHostname   string
	PostfixDBHost     string
	PostfixDBPort     int
	PostfixDBName     string
	PostfixDBUser     string
	PostfixDBPassword string
	DovecotConfigDir  string
	DovecotDBHost     string
	DovecotDBPort     int
	DovecotDBName     string
	DovecotDBUser     string
	DovecotDBPassword string
	TLSBaseDir        string

	TLSHostname       string
	DKIMBaseDir       string
	OpenDKIMConfigDir string
	OpenDKIMSocket    string
	IdentityProvider  string
	LDAPURL           string
	LDAPBaseDN       string
	LDAPBindDN        string
	LDAPBindPassword  string
	VmailDir          string
}



func Load() (*Config, error) {
	// Silently attempt to load .env if present
	_ = godotenv.Load()

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		dbURL = "postgres://mailopen:mailopen@localhost:5432/mailopen?sslmode=disable"
	}

	storagePath := os.Getenv("STORAGE_PATH")
	if storagePath == "" {
		storagePath = "./data/blobs"
	}

	vmailRoot := os.Getenv("VMAIL_ROOT")
	if vmailRoot == "" {
		vmailRoot = "./data/vmail"
	}

	vmailUID := 5000
	if val := os.Getenv("VMAIL_UID"); val != "" {
		if parsed, err := strconv.Atoi(val); err == nil {
			vmailUID = parsed
		}
	}

	vmailGID := 5000
	if val := os.Getenv("VMAIL_GID"); val != "" {
		if parsed, err := strconv.Atoi(val); err == nil {
			vmailGID = parsed
		}
	}

	postfixConfigDir := os.Getenv("POSTFIX_CONFIG_DIR")
	if postfixConfigDir == "" {
		postfixConfigDir = "./data/postfix"
	}

	postfixHostname := os.Getenv("POSTFIX_HOSTNAME")
	if postfixHostname == "" {
		postfixHostname = "mail.example.com"
	}

	postfixDBHost := os.Getenv("POSTFIX_DB_HOST")
	if postfixDBHost == "" {
		postfixDBHost = "127.0.0.1"
	}

	postfixDBPort := 5432
	if val := os.Getenv("POSTFIX_DB_PORT"); val != "" {
		if parsed, err := strconv.Atoi(val); err == nil {
			postfixDBPort = parsed
		}
	}

	postfixDBName := os.Getenv("POSTFIX_DB_NAME")
	if postfixDBName == "" {
		postfixDBName = "mailopen"
	}

	postfixDBUser := os.Getenv("POSTFIX_DB_USER")
	if postfixDBUser == "" {
		postfixDBUser = "mailopen_postfix"
	}

	postfixDBPassword := os.Getenv("POSTFIX_DB_PASSWORD")
	if postfixDBPassword == "" {
		postfixDBPassword = "postfix_secret"
	}

	dovecotConfigDir := os.Getenv("DOVECOT_CONFIG_DIR")
	if dovecotConfigDir == "" {
		dovecotConfigDir = "./data/dovecot"
	}

	dovecotDBHost := os.Getenv("DOVECOT_DB_HOST")
	if dovecotDBHost == "" {
		dovecotDBHost = "127.0.0.1"
	}

	dovecotDBPort := 5432
	if val := os.Getenv("DOVECOT_DB_PORT"); val != "" {
		if parsed, err := strconv.Atoi(val); err == nil {
			dovecotDBPort = parsed
		}
	}

	dovecotDBName := os.Getenv("DOVECOT_DB_NAME")
	if dovecotDBName == "" {
		dovecotDBName = "mailopen"
	}

	dovecotDBUser := os.Getenv("DOVECOT_DB_USER")
	if dovecotDBUser == "" {
		dovecotDBUser = "mailopen_dovecot"
	}

	dovecotDBPassword := os.Getenv("DOVECOT_DB_PASSWORD")
	if dovecotDBPassword == "" {
		dovecotDBPassword = "dovecot_secret"
	}

	tlsBaseDir := os.Getenv("TLS_BASE_DIR")
	if tlsBaseDir == "" {
		tlsBaseDir = "./data/tls"
	}

	tlsHostname := os.Getenv("TLS_HOSTNAME")
	if tlsHostname == "" {
		tlsHostname = postfixHostname
	}

	dkimBaseDir := os.Getenv("DKIM_BASE_DIR")
	if dkimBaseDir == "" {
		dkimBaseDir = "./data/dkim"
	}

	openDKIMConfigDir := os.Getenv("OPENDKIM_CONFIG_DIR")
	if openDKIMConfigDir == "" {
		openDKIMConfigDir = "./data/opendkim"
	}

	openDKIMSocket := os.Getenv("OPENDKIM_SOCKET")
	if openDKIMSocket == "" {
		openDKIMSocket = "/var/spool/postfix/private/opendkim"
	}

	identityProvider := os.Getenv("IDENTITY_PROVIDER")
	if identityProvider == "" {
		identityProvider = "local"
	}

	ldapURL := os.Getenv("LDAP_URL")
	ldapBaseDN := os.Getenv("LDAP_BASE_DN")
	ldapBindDN := os.Getenv("LDAP_BIND_DN")
	ldapBindPassword := os.Getenv("LDAP_BIND_PASSWORD")

	return &Config{
		DatabaseURL:       dbURL,
		StoragePath:       storagePath,
		VmailRoot:         vmailRoot,
		VmailDir:          vmailRoot,
		VmailUID:          vmailUID,
		VmailGID:          vmailGID,
		PostfixConfigDir:  postfixConfigDir,
		PostfixHostname:   postfixHostname,
		PostfixDBHost:     postfixDBHost,
		PostfixDBPort:     postfixDBPort,
		PostfixDBName:     postfixDBName,
		PostfixDBUser:     postfixDBUser,
		PostfixDBPassword: postfixDBPassword,
		DovecotConfigDir:  dovecotConfigDir,
		DovecotDBHost:     dovecotDBHost,
		DovecotDBPort:     dovecotDBPort,
		DovecotDBName:     dovecotDBName,
		DovecotDBUser:     dovecotDBUser,
		DovecotDBPassword: dovecotDBPassword,
		TLSBaseDir:        tlsBaseDir,
		TLSHostname:       tlsHostname,
		DKIMBaseDir:       dkimBaseDir,
		OpenDKIMConfigDir: openDKIMConfigDir,
		OpenDKIMSocket:    openDKIMSocket,
		IdentityProvider:  identityProvider,
		LDAPURL:           ldapURL,
		LDAPBaseDN:        ldapBaseDN,
		LDAPBindDN:        ldapBindDN,
		LDAPBindPassword:  ldapBindPassword,
	}, nil
}



