package config

import (
	"os"
	"strconv"

	"github.com/joho/godotenv"
)

type Config struct {
	DatabaseURL string
	StoragePath string
	VmailRoot   string
	VmailUID    int
	VmailGID    int
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

	return &Config{
		DatabaseURL: dbURL,
		StoragePath: storagePath,
		VmailRoot:   vmailRoot,
		VmailUID:    vmailUID,
		VmailGID:    vmailGID,
	}, nil
}
