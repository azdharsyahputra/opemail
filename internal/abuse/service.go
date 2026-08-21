package abuse

import (
	"context"
	"errors"
	"strings"

	"github.com/azdharsyahputra/openmail/internal/mailbox"
)

type Service interface {
	GetLimits(ctx context.Context, email string) (*MailboxLimits, error)
	SetLimits(ctx context.Context, email string, limits *MailboxLimits) error
}

type service struct {
	repo        Repository
	mailboxRepo mailbox.Repository
}

func NewService(repo Repository, mailboxRepo mailbox.Repository) Service {
	return &service{
		repo:        repo,
		mailboxRepo: mailboxRepo,
	}
}

func (s *service) GetLimits(ctx context.Context, email string) (*MailboxLimits, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	mb, err := s.mailboxRepo.GetByEmail(ctx, email)
	if err != nil {
		return nil, err
	}

	limits, err := s.repo.GetLimits(ctx, mb.ID)
	if err != nil {
		if errors.Is(err, ErrLimitsNotFound) {
			// Return default baseline limits
			return &MailboxLimits{
				MailboxID:         mb.ID,
				Email:             email,
				MessagesPerMinute: 30,
				MessagesPerHour:   300,
				RecipientsPerDay:  1000,
				Enabled:           true,
			}, nil
		}
		return nil, err
	}
	return limits, nil
}

func (s *service) SetLimits(ctx context.Context, email string, limits *MailboxLimits) error {
	email = strings.ToLower(strings.TrimSpace(email))
	mb, err := s.mailboxRepo.GetByEmail(ctx, email)
	if err != nil {
		return err
	}

	limits.MailboxID = mb.ID
	limits.Email = email
	return s.repo.UpsertLimits(ctx, limits)
}
