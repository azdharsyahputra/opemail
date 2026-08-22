package webmail

import (
	"context"
	"time"
)

type Folder struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	TotalCount  int    `json:"total_count"`
	UnreadCount int    `json:"unread_count"`
	Icon        string `json:"icon"`
}

type Attachment struct {
	ID          string `json:"id"`
	Filename    string `json:"filename"`
	ContentType string `json:"content_type"`
	Size        int64  `json:"size"`
	ContentID   string `json:"content_id,omitempty"`
}

type MessageSummary struct {
	ID             string    `json:"id"`
	Folder         string    `json:"folder"`
	MessageID      string    `json:"message_id"`
	From           string    `json:"from"`
	To             []string  `json:"to"`
	Subject        string    `json:"subject"`
	Date           time.Time `json:"date"`
	IsRead         bool      `json:"is_read"`
	IsStarred      bool      `json:"is_starred"`
	HasAttachments bool      `json:"has_attachments"`
	Size           int64     `json:"size"`
	Snippet        string    `json:"snippet"`
}

type MessageDetail struct {
	MessageSummary
	Cc          []string            `json:"cc,omitempty"`
	Bcc         []string            `json:"bcc,omitempty"`
	ReplyTo     string              `json:"reply_to,omitempty"`
	BodyText    string              `json:"body_text"`
	BodyHTML    string              `json:"body_html"`
	Attachments []Attachment        `json:"attachments"`
	Headers     map[string][]string `json:"headers,omitempty"`
}

type SendMessageRequest struct {
	To          []string      `json:"to"`
	Cc          []string      `json:"cc,omitempty"`
	Bcc         []string      `json:"bcc,omitempty"`
	Subject     string        `json:"subject"`
	BodyText    string        `json:"body_text,omitempty"`
	BodyHTML    string        `json:"body_html,omitempty"`
	InReplyTo   string        `json:"in_reply_to,omitempty"`
	References  string        `json:"references,omitempty"`
	Attachments []IncomingAtt `json:"attachments,omitempty"`
}

type IncomingAtt struct {
	Filename    string `json:"filename"`
	ContentType string `json:"content_type"`
	DataB64     string `json:"data_b64"`
}

type Service interface {
	ListFolders(ctx context.Context, email string) ([]Folder, error)
	ListMessages(ctx context.Context, email, folder string, page, limit int, search string) ([]MessageSummary, int, error)
	GetMessage(ctx context.Context, email, folder, messageID string) (*MessageDetail, error)
	SendMessage(ctx context.Context, fromEmail string, req SendMessageRequest) (*MessageSummary, error)
	MarkMessageRead(ctx context.Context, email, folder, messageID string, read bool) error
	MoveMessage(ctx context.Context, email, srcFolder, dstFolder, messageID string) error
	DeleteMessage(ctx context.Context, email, folder, messageID string) error
	GetAttachment(ctx context.Context, email, folder, messageID, attachmentID string) (string, string, []byte, error)
}
