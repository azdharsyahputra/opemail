package quota

import (
	"errors"

	"github.com/google/uuid"
)

var (
	ErrQuotaExceeded = errors.New("552 5.2.2 Mailbox is full / quota exceeded")
)

type Status string

const (
	StatusOK       Status = "OK"       // < 80%
	StatusWarning  Status = "WARNING"  // 80 - 89%
	StatusCritical Status = "CRITICAL" // 90 - 99%
	StatusFull     Status = "FULL"     // >= 100%
)

type MailboxQuota struct {
	MailboxID    uuid.UUID `json:"mailbox_id"`
	Email        string    `json:"email"`
	UsedBytes    int64     `json:"used_bytes"`
	QuotaBytes   int64     `json:"quota_bytes"`
	UsagePercent float64   `json:"usage_percent"`
	Status       Status    `json:"status"`
	IsExceeded   bool      `json:"is_exceeded"`
	MessageCount int64     `json:"message_count"`
}
