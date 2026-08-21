package message

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"
)

type Repository interface {
	Create(ctx context.Context, m *Message) error
	GetByID(ctx context.Context, id uuid.UUID) (*Message, error)
	ListByMailbox(ctx context.Context, mailboxID uuid.UUID) ([]*Message, error)
	Delete(ctx context.Context, id uuid.UUID) error
}

type postgresRepository struct {
	db *sql.DB
}

func NewPostgresRepository(db *sql.DB) Repository {
	return &postgresRepository{db: db}
}

func (r *postgresRepository) Create(ctx context.Context, m *Message) error {
	query := `
		INSERT INTO messages (id, mailbox_id, message_id, blob_id, sender, subject, size_bytes, received_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`
	_, err := r.db.ExecContext(ctx, query, m.ID, m.MailboxID, m.MessageID, m.BlobID, m.Sender, m.Subject, m.SizeBytes, m.ReceivedAt, m.CreatedAt)
	if err != nil {
		return fmt.Errorf("repository create message: %w", err)
	}
	return nil
}

func (r *postgresRepository) GetByID(ctx context.Context, id uuid.UUID) (*Message, error) {
	query := `
		SELECT id, mailbox_id, message_id, blob_id, sender, subject, size_bytes, received_at, created_at
		FROM messages
		WHERE id = $1
	`
	m := &Message{}
	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&m.ID, &m.MailboxID, &m.MessageID, &m.BlobID, &m.Sender, &m.Subject, &m.SizeBytes, &m.ReceivedAt, &m.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrMessageNotFound
		}
		return nil, fmt.Errorf("repository get message by id: %w", err)
	}
	return m, nil
}

func (r *postgresRepository) ListByMailbox(ctx context.Context, mailboxID uuid.UUID) ([]*Message, error) {
	query := `
		SELECT id, mailbox_id, message_id, blob_id, sender, subject, size_bytes, received_at, created_at
		FROM messages
		WHERE mailbox_id = $1
		ORDER BY received_at DESC
	`
	rows, err := r.db.QueryContext(ctx, query, mailboxID)
	if err != nil {
		return nil, fmt.Errorf("repository list messages: %w", err)
	}
	defer rows.Close()

	var messages []*Message
	for rows.Next() {
		m := &Message{}
		if err := rows.Scan(
			&m.ID, &m.MailboxID, &m.MessageID, &m.BlobID, &m.Sender, &m.Subject, &m.SizeBytes, &m.ReceivedAt, &m.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("repository scan message: %w", err)
		}
		messages = append(messages, m)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return messages, nil
}

func (r *postgresRepository) Delete(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM messages WHERE id = $1`
	res, err := r.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("repository delete message: %w", err)
	}
	rowsAffected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		return ErrMessageNotFound
	}
	return nil
}
