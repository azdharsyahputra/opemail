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

	return &Config{
		DatabaseURL:       dbURL,
		StoragePath:       storagePath,
		VmailRoot:         vmailRoot,
		VmailUID:          vmailUID,
		VmailGID:          vmailGID,
		PostfixConfigDir:  postfixConfigDir,
		PostfixHostname:   postfixHostname,
		PostfixDBHost:     postfixDBHost,
		PostfixDBPort:     postfixDBPort,
		PostfixDBName:     postfixDBName,
		PostfixDBUser:     postfixDBUser,
		PostfixDBPassword: postfixDBPassword,
	}, nil
}
