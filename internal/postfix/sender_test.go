package postfix_test

import (
	"context"
	"testing"

	"github.com/azdharsyahputra/openmail/internal/postfix"
)

type mockSenderAuthorizer struct {
	authorized map[string][]string // user -> allowed senders
}

var _ postfix.SenderAuthorizer = (*mockSenderAuthorizer)(nil)

func newMockSenderAuthorizer() *mockSenderAuthorizer {
	return &mockSenderAuthorizer{
		authorized: make(map[string][]string),
	}
}



func (m *mockSenderAuthorizer) CanSendAs(ctx context.Context, authenticatedUser, sender string) (bool, error) {
	senders, ok := m.authorized[authenticatedUser]
	if !ok {
		return false, nil
	}
	for _, s := range senders {
		if s == sender {
			return true, nil
		}
	}
	return false, nil
}

func TestSenderAuthorizationMatrix(t *testing.T) {
	auth := newMockSenderAuthorizer()
	ctx := context.Background()

	auth.authorized["ajar@example.com"] = []string{
		"ajar@example.com",
		"support@example.com",
	}

	t.Run("AUTH ajar -> ajar@ (primary sender) -> PASS", func(t *testing.T) {
		canSend, err := auth.CanSendAs(ctx, "ajar@example.com", "ajar@example.com")
		if err != nil || !canSend {
			t.Errorf("expected primary sender to be authorized, got canSend=%v err=%v", canSend, err)
		}
	})

	t.Run("AUTH ajar -> authorized alias (support@) -> PASS", func(t *testing.T) {
		canSend, err := auth.CanSendAs(ctx, "ajar@example.com", "support@example.com")
		if err != nil || !canSend {
			t.Errorf("expected authorized alias to be allowed, got canSend=%v err=%v", canSend, err)
		}
	})

	t.Run("AUTH ajar -> unauthorized sender (ceo@bank.com) -> FAIL", func(t *testing.T) {
		canSend, err := auth.CanSendAs(ctx, "ajar@example.com", "ceo@bank.com")
		if err != nil || canSend {
			t.Errorf("expected unauthorized sender to be rejected, got canSend=%v", canSend)
		}
	})

	t.Run("No AUTH / unknown user -> external -> FAIL", func(t *testing.T) {
		canSend, err := auth.CanSendAs(ctx, "ghost@example.com", "someone@gmail.com")
		if err != nil || canSend {
			t.Errorf("expected unknown user to be rejected, got canSend=%v", canSend)
		}
	})
}
