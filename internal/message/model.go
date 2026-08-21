package message

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

var (
	ErrMessageNotFound = errors.New("message not found")
	ErrMailboxNotFound = errors.New("mailbox not found")
	ErrInvalidMessage  = errors.New("invalid message data")
)

type Message struct {
	ID         uuid.UUID `json:"id"`
	MailboxID  uuid.UUID `json:"mailbox_id"`
	MessageID  string    `json:"message_id"`
	BlobID     string    `json:"blob_id"`
	Sender     string    `json:"sender"`
	Subject    string    `json:"subject"`
	SizeBytes  int64     `json:"size_bytes"`
	ReceivedAt time.Time `json:"received_at"`
	CreatedAt  time.Time `json:"created_at"`
}
