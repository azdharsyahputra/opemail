package message

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/mail"
	"strings"
	"time"

	"github.com/azdharsyahputra/openmail/internal/mailbox"
	"github.com/azdharsyahputra/openmail/internal/storage"
	"github.com/google/uuid"
)

type Service interface {
	Store(ctx context.Context, mailboxEmail string, rawEmail io.Reader) (*Message, error)
	GetByID(ctx context.Context, id uuid.UUID) (*Message, error)
	GetContent(ctx context.Context, id uuid.UUID) (*Message, io.ReadCloser, error)
	ListByMailbox(ctx context.Context, mailboxEmail string) ([]*Message, error)
	Delete(ctx context.Context, id uuid.UUID) error
}

type service struct {
	messageRepo Repository
	mailboxRepo mailbox.Repository
	blobStore   storage.BlobStore
}

func NewService(messageRepo Repository, mailboxRepo mailbox.Repository, blobStore storage.BlobStore) Service {
	return &service{
		messageRepo: messageRepo,
		mailboxRepo: mailboxRepo,
		blobStore:   blobStore,
	}
}

func (s *service) Store(ctx context.Context, mailboxEmail string, rawEmail io.Reader) (*Message, error) {
	if rawEmail == nil {
		return nil, storage.ErrEmptyPayload
	}

	mailboxEmail = strings.TrimSpace(strings.ToLower(mailboxEmail))
	mb, err := s.mailboxRepo.GetByEmail(ctx, mailboxEmail)
	if err != nil {
		if errors.Is(err, mailbox.ErrMailboxNotFound) {
			return nil, ErrMailboxNotFound
		}
		return nil, fmt.Errorf("resolving mailbox: %w", err)
	}

	// 1. Read the raw email data into memory or buffer for header parsing and blob storage
	var rawBuf bytes.Buffer
	if _, err := io.Copy(&rawBuf, rawEmail); err != nil {
		return nil, fmt.Errorf("reading raw email stream: %w", err)
	}

	rawBytes := rawBuf.Bytes()
	if len(rawBytes) == 0 {
		return nil, storage.ErrEmptyPayload
	}

	// 2. Parse RFC 5322 headers
	msgID, sender, subject, receivedAt := parseEmailHeaders(rawBytes)

	// 3. Put into BlobStore
	blob, err := s.blobStore.Put(ctx, bytes.NewReader(rawBytes))
	if err != nil {
		return nil, fmt.Errorf("storing payload in blobstore: %w", err)
	}

	// 4. Save metadata in database
	now := time.Now().UTC()
	if receivedAt.IsZero() {
		receivedAt = now
	}

	msg := &Message{
		ID:         uuid.New(),
		MailboxID:  mb.ID,
		MessageID:  msgID,
		BlobID:     blob.ID,
		Sender:     sender,
		Subject:    subject,
		SizeBytes:  blob.SizeBytes,
		ReceivedAt: receivedAt,
		CreatedAt:  now,
	}

	if err := s.messageRepo.Create(ctx, msg); err != nil {
		// Clean up blob if DB write fails
		_ = s.blobStore.Delete(ctx, blob.ID)
		return nil, fmt.Errorf("saving message metadata: %w", err)
	}

	return msg, nil
}

func (s *service) GetByID(ctx context.Context, id uuid.UUID) (*Message, error) {
	return s.messageRepo.GetByID(ctx, id)
}

func (s *service) GetContent(ctx context.Context, id uuid.UUID) (*Message, io.ReadCloser, error) {
	msg, err := s.messageRepo.GetByID(ctx, id)
	if err != nil {
		return nil, nil, err
	}

	reader, err := s.blobStore.Get(ctx, msg.BlobID)
	if err != nil {
		return nil, nil, fmt.Errorf("reading payload from blobstore: %w", err)
	}

	return msg, reader, nil
}

func (s *service) ListByMailbox(ctx context.Context, mailboxEmail string) ([]*Message, error) {
	mailboxEmail = strings.TrimSpace(strings.ToLower(mailboxEmail))
	mb, err := s.mailboxRepo.GetByEmail(ctx, mailboxEmail)
	if err != nil {
		if errors.Is(err, mailbox.ErrMailboxNotFound) {
			return nil, ErrMailboxNotFound
		}
		return nil, fmt.Errorf("resolving mailbox: %w", err)
	}

	return s.messageRepo.ListByMailbox(ctx, mb.ID)
}

func (s *service) Delete(ctx context.Context, id uuid.UUID) error {
	msg, err := s.messageRepo.GetByID(ctx, id)
	if err != nil {
		return err
	}

	if err := s.messageRepo.Delete(ctx, id); err != nil {
		return err
	}

	// Clean up blob file
	_ = s.blobStore.Delete(ctx, msg.BlobID)
	return nil
}

func parseEmailHeaders(raw []byte) (messageID, sender, subject string, date time.Time) {
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		// If raw content is not RFC 5322 formatted, fallback to default values
		return "", "", "", time.Time{}
	}

	messageID = msg.Header.Get("Message-ID")
	if messageID == "" {
		messageID = msg.Header.Get("Message-Id")
	}

	sender = msg.Header.Get("From")
	if sender == "" {
		sender = msg.Header.Get("Sender")
	}

	subject = msg.Header.Get("Subject")

	dateStr := msg.Header.Get("Date")
	if dateStr != "" {
		if parsedDate, err := mail.ParseDate(dateStr); err == nil {
			date = parsedDate.UTC()
		}
	}

	return messageID, sender, subject, date
}
