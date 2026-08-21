package config

import (
	"os"

	"github.com/joho/godotenv"
)

type Config struct {
	DatabaseURL string
}

func Load() (*Config, error) {
	// Silently attempt to load .env if present
	_ = godotenv.Load()

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		dbURL = "postgres://mailopen:mailopen@localhost:5432/mailopen?sslmode=disable"
	}

	return &Config{
		DatabaseURL: dbURL,
	}, nil
}
