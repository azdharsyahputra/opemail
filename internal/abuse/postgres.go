package abuse

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"
)

type PostgresRepository struct {
	db *sql.DB
}

func NewPostgresRepository(db *sql.DB) *PostgresRepository {
	return &PostgresRepository{db: db}
}

func (r *PostgresRepository) GetLimits(ctx context.Context, mailboxID uuid.UUID) (*MailboxLimits, error) {
	query := `
		SELECT l.mailbox_id, m.email, l.messages_per_minute, l.messages_per_hour,
		       l.recipients_per_day, l.enabled, l.created_at, l.updated_at
		FROM mailbox_limits l
		JOIN mailboxes m ON m.id = l.mailbox_id
		WHERE l.mailbox_id = $1;
	`
	var l MailboxLimits
	err := r.db.QueryRowContext(ctx, query, mailboxID).Scan(
		&l.MailboxID,
		&l.Email,
		&l.MessagesPerMinute,
		&l.MessagesPerHour,
		&l.RecipientsPerDay,
		&l.Enabled,
		&l.CreatedAt,
		&l.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrLimitsNotFound
		}
		return nil, fmt.Errorf("get mailbox limits: %w", err)
	}
	return &l, nil
}

func (r *PostgresRepository) UpsertLimits(ctx context.Context, l *MailboxLimits) error {
	query := `
		INSERT INTO mailbox_limits (
			mailbox_id, messages_per_minute, messages_per_hour, recipients_per_day, enabled, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, NOW(), NOW())
		ON CONFLICT (mailbox_id) DO UPDATE
		SET messages_per_minute = EXCLUDED.messages_per_minute,
		    messages_per_hour = EXCLUDED.messages_per_hour,
		    recipients_per_day = EXCLUDED.recipients_per_day,
		    enabled = EXCLUDED.enabled,
		    updated_at = NOW();
	`
	_, err := r.db.ExecContext(ctx, query,
		l.MailboxID,
		l.MessagesPerMinute,
		l.MessagesPerHour,
		l.RecipientsPerDay,
		l.Enabled,
	)
	if err != nil {
		return fmt.Errorf("upsert mailbox limits: %w", err)
	}
	return nil
}
