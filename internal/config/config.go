package config

import (
	"os"

	"github.com/joho/godotenv"
)

type Config struct {
	DatabaseURL string
	StoragePath string
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

	return &Config{
		DatabaseURL: dbURL,
		StoragePath: storagePath,
	}, nil
}
