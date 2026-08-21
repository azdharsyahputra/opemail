package database

import (
	"database/sql"
	"fmt"

	"github.com/azdharsyahputra/openmail/migrations"
	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	_ "github.com/jackc/pgx/v5/stdlib"
)

func NewPostgresDB(databaseURL string) (*sql.DB, error) {
	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to open database connection: %w", err)
	}

	db.SetMaxOpenConns(50)
	db.SetMaxIdleConns(25)

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return db, nil
}


func RunMigrationsUp(db *sql.DB) error {
	driver, err := postgres.WithInstance(db, &postgres.Config{})
	if err != nil {
		return fmt.Errorf("could not create postgres driver for migration: %w", err)
	}

	sourceDriver, err := iofs.New(migrations.FS, ".")
	if err != nil {
		return fmt.Errorf("could not create iofs source for migration: %w", err)
	}

	m, err := migrate.NewWithInstance("iofs", sourceDriver, "postgres", driver)
	if err != nil {
		return fmt.Errorf("could not create migrate instance: %w", err)
	}

	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		return fmt.Errorf("migration up failed: %w", err)
	}

	return nil
}

func RunMigrationsDown(db *sql.DB) error {
	driver, err := postgres.WithInstance(db, &postgres.Config{})
	if err != nil {
		return fmt.Errorf("could not create postgres driver for migration: %w", err)
	}

	sourceDriver, err := iofs.New(migrations.FS, ".")
	if err != nil {
		return fmt.Errorf("could not create iofs source for migration: %w", err)
	}

	m, err := migrate.NewWithInstance("iofs", sourceDriver, "postgres", driver)
	if err != nil {
		return fmt.Errorf("could not create migrate instance: %w", err)
	}

	if err := m.Down(); err != nil && err != migrate.ErrNoChange {
		// If migration is dirty or failed, drop schema migrations to reset
		_, _ = db.Exec("DROP TABLE IF EXISTS schema_migrations CASCADE;")
		return fmt.Errorf("migration down failed: %w", err)
	}

	return nil
}

func DropAllTables(db *sql.DB) error {
	_, err := db.Exec(`
		DROP TABLE IF EXISTS messages CASCADE;
		DROP TABLE IF EXISTS aliases CASCADE;
		DROP TABLE IF EXISTS mailboxes CASCADE;
		DROP TABLE IF EXISTS domains CASCADE;
		DROP TABLE IF EXISTS schema_migrations CASCADE;
	`)
	return err
}

