package system

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

type Setting struct {
	Key         string    `json:"key"`
	Value       string    `json:"value"`
	Category    string    `json:"category"`
	Description string    `json:"description"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type SettingRepository interface {
	GetAll(ctx context.Context) (map[string]Setting, error)
	Get(ctx context.Context, key string) (*Setting, error)
	Set(ctx context.Context, key, value string) error
	SetBatch(ctx context.Context, settings map[string]string) error
}

type PostgresSettingRepository struct {
	db *sql.DB
}

func NewPostgresSettingRepository(db *sql.DB) *PostgresSettingRepository {
	return &PostgresSettingRepository{db: db}
}

func (r *PostgresSettingRepository) GetAll(ctx context.Context) (map[string]Setting, error) {
	query := `SELECT key, value, category, description, updated_at FROM system_settings ORDER BY category, key`
	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query system_settings: %w", err)
	}
	defer rows.Close()

	res := make(map[string]Setting)
	for rows.Next() {
		var s Setting
		if err := rows.Scan(&s.Key, &s.Value, &s.Category, &s.Description, &s.UpdatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan setting: %w", err)
		}
		res[s.Key] = s
	}
	return res, rows.Err()
}

func (r *PostgresSettingRepository) Get(ctx context.Context, key string) (*Setting, error) {
	query := `SELECT key, value, category, description, updated_at FROM system_settings WHERE key = $1`
	var s Setting
	err := r.db.QueryRowContext(ctx, query, key).Scan(&s.Key, &s.Value, &s.Category, &s.Description, &s.UpdatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &s, nil
}

func (r *PostgresSettingRepository) Set(ctx context.Context, key, value string) error {
	query := `
		INSERT INTO system_settings (key, value, updated_at)
		VALUES ($1, $2, NOW())
		ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()
	`
	_, err := r.db.ExecContext(ctx, query, key, value)
	return err
}

func (r *PostgresSettingRepository) SetBatch(ctx context.Context, settings map[string]string) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO system_settings (key, value, updated_at)
		VALUES ($1, $2, NOW())
		ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for k, v := range settings {
		if _, err := stmt.ExecContext(ctx, k, v); err != nil {
			return err
		}
	}

	return tx.Commit()
}
