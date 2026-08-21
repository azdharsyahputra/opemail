package abuse

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

var (
	ErrLimitsNotFound = errors.New("mailbox abuse limits not found")
)

type MailboxLimits struct {
	MailboxID         uuid.UUID `json:"mailbox_id"`
	Email             string    `json:"email,omitempty"`
	MessagesPerMinute int       `json:"messages_per_minute"`
	MessagesPerHour   int       `json:"messages_per_hour"`
	RecipientsPerDay  int       `json:"recipients_per_day"`
	Enabled           bool      `json:"enabled"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}
