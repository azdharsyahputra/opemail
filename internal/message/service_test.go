package message_test

import (
	"bytes"
	"context"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/azdharsyahputra/openmail/internal/mailbox"
	"github.com/azdharsyahputra/openmail/internal/message"
	"github.com/azdharsyahputra/openmail/internal/storage"
	"github.com/google/uuid"
)

type mockMailboxRepo struct {
	mu        sync.Mutex
	mailboxes map[string]*mailbox.Mailbox
}

func newMockMailboxRepo() *mockMailboxRepo {
	return &mockMailboxRepo{mailboxes: make(map[string]*mailbox.Mailbox)}
}

func (m *mockMailboxRepo) Create(ctx context.Context, mb *mailbox.Mailbox) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.mailboxes[mb.Email] = mb
	return nil
}

func (m *mockMailboxRepo) GetByEmail(ctx context.Context, email string) (*mailbox.Mailbox, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	mb, ok := m.mailboxes[email]
	if !ok {
		return nil, mailbox.ErrMailboxNotFound
	}
	return mb, nil
}

func (m *mockMailboxRepo) GetByID(ctx context.Context, id uuid.UUID) (*mailbox.Mailbox, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, mb := range m.mailboxes {
		if mb.ID == id {
			return mb, nil
		}
	}
	return nil, mailbox.ErrMailboxNotFound
}

func (m *mockMailboxRepo) List(ctx context.Context) ([]*mailbox.Mailbox, error) {
	return nil, nil
}

func (m *mockMailboxRepo) UpdateProvisioningStatus(ctx context.Context, id uuid.UUID, status string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, mb := range m.mailboxes {
		if mb.ID == id {
			mb.ProvisioningStatus = status
			return nil
		}
	}
	return mailbox.ErrMailboxNotFound
}

func (m *mockMailboxRepo) UpdateStatus(ctx context.Context, id uuid.UUID, status string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, mb := range m.mailboxes {
		if mb.ID == id {
			mb.Status = status
			return nil
		}
	}
	return mailbox.ErrMailboxNotFound
}

func (m *mockMailboxRepo) Delete(ctx context.Context, email string) error {
	return nil
}


type mockMessageRepo struct {
	mu       sync.Mutex
	messages map[uuid.UUID]*message.Message
}

func newMockMessageRepo() *mockMessageRepo {
	return &mockMessageRepo{messages: make(map[uuid.UUID]*message.Message)}
}

func (r *mockMessageRepo) Create(ctx context.Context, m *message.Message) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.messages[m.ID] = m
	return nil
}

func (r *mockMessageRepo) GetByID(ctx context.Context, id uuid.UUID) (*message.Message, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	m, ok := r.messages[id]
	if !ok {
		return nil, message.ErrMessageNotFound
	}
	return m, nil
}

func (r *mockMessageRepo) ListByMailbox(ctx context.Context, mailboxID uuid.UUID) ([]*message.Message, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var list []*message.Message
	for _, m := range r.messages {
		if m.MailboxID == mailboxID {
			list = append(list, m)
		}
	}
	return list, nil
}

func (r *mockMessageRepo) GetAllBlobIDs(ctx context.Context) (map[string]bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	blobIDs := make(map[string]bool)
	for _, m := range r.messages {
		blobIDs[m.BlobID] = true
	}
	return blobIDs, nil
}

func (r *mockMessageRepo) Delete(ctx context.Context, id uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.messages[id]; !ok {
		return message.ErrMessageNotFound
	}
	delete(r.messages, id)
	return nil
}


func TestMessageService(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "openmail-msg-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	blobStore, err := storage.NewFilesystemBlobStore(tempDir)
	if err != nil {
		t.Fatalf("failed to create blob store: %v", err)
	}

	mbRepo := newMockMailboxRepo()
	msgRepo := newMockMessageRepo()
	svc := message.NewService(msgRepo, mbRepo, blobStore)
	ctx := context.Background()

	// Seed mailbox
	mb := &mailbox.Mailbox{
		ID:        uuid.New(),
		DomainID:  uuid.New(),
		Email:     "ajar@example.com",
		Status:    "active",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	_ = mbRepo.Create(ctx, mb)

	sampleEmail := "Message-ID: <12345@example.com>\r\n" +
		"From: sender@domain.com\r\n" +
		"To: ajar@example.com\r\n" +
		"Subject: Weekly Report\r\n" +
		"Date: Fri, 21 Aug 2026 12:00:00 +0000\r\n\r\n" +
		"Here is the report..."

	t.Run("Store valid message", func(t *testing.T) {
		msg, err := svc.Store(ctx, "ajar@example.com", strings.NewReader(sampleEmail))
		if err != nil {
			t.Fatalf("expected no error storing message, got %v", err)
		}

		if msg.MailboxID != mb.ID {
			t.Errorf("expected mailbox ID %s, got %s", mb.ID, msg.MailboxID)
		}
		if msg.Sender != "sender@domain.com" {
			t.Errorf("expected sender sender@domain.com, got %s", msg.Sender)
		}
		if msg.Subject != "Weekly Report" {
			t.Errorf("expected subject 'Weekly Report', got %s", msg.Subject)
		}
		if msg.MessageID != "<12345@example.com>" {
			t.Errorf("expected message-id <12345@example.com>, got %s", msg.MessageID)
		}
		if msg.BlobID == "" {
			t.Error("expected non-empty blob ID")
		}

		// Verify blob is stored in BlobStore
		exists, err := blobStore.Exists(ctx, msg.BlobID)
		if err != nil || !exists {
			t.Errorf("expected blob to exist in blobstore, exists=%v, err=%v", exists, err)
		}
	})

	t.Run("Store message for nonexistent mailbox", func(t *testing.T) {
		_, err := svc.Store(ctx, "nonexistent@example.com", strings.NewReader(sampleEmail))
		if err != message.ErrMailboxNotFound {
			t.Errorf("expected ErrMailboxNotFound, got %v", err)
		}
	})

	t.Run("Store empty payload", func(t *testing.T) {
		_, err := svc.Store(ctx, "ajar@example.com", strings.NewReader(""))
		if err != storage.ErrEmptyPayload {
			t.Errorf("expected ErrEmptyPayload, got %v", err)
		}
	})

	t.Run("GetContent retrieves message and body stream", func(t *testing.T) {
		msg, err := svc.Store(ctx, "ajar@example.com", strings.NewReader(sampleEmail))
		if err != nil {
			t.Fatalf("failed to store message: %v", err)
		}

		gotMsg, reader, err := svc.GetContent(ctx, msg.ID)
		if err != nil {
			t.Fatalf("failed to get content: %v", err)
		}
		defer reader.Close()

		if gotMsg.ID != msg.ID {
			t.Errorf("expected msg ID %s, got %s", msg.ID, gotMsg.ID)
		}

		buf := new(bytes.Buffer)
		_, err = io.Copy(buf, reader)
		if err != nil {
			t.Fatalf("failed to read payload: %v", err)
		}

		if buf.String() != sampleEmail {
			t.Errorf("expected content %q, got %q", sampleEmail, buf.String())
		}
	})

	t.Run("ListByMailbox", func(t *testing.T) {
		list, err := svc.ListByMailbox(ctx, "ajar@example.com")
		if err != nil {
			t.Fatalf("failed to list messages: %v", err)
		}
		if len(list) < 2 {
			t.Errorf("expected at least 2 messages, got %d", len(list))
		}
	})

	t.Run("Delete message and blob cleanup", func(t *testing.T) {
		msg, err := svc.Store(ctx, "ajar@example.com", strings.NewReader(sampleEmail))
		if err != nil {
			t.Fatalf("failed to store message: %v", err)
		}

		err = svc.Delete(ctx, msg.ID)
		if err != nil {
			t.Fatalf("failed to delete message: %v", err)
		}

		_, err = svc.GetByID(ctx, msg.ID)
		if err != message.ErrMessageNotFound {
			t.Errorf("expected ErrMessageNotFound, got %v", err)
		}

		exists, err := blobStore.Exists(ctx, msg.BlobID)
		if err != nil || exists {
			t.Errorf("expected blob to be deleted, exists=%v, err=%v", exists, err)
		}
	})
}
