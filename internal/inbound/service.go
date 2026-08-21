package inbound

import (
	"context"
	"database/sql"
	"time"

	"github.com/azdharsyahputra/openmail/internal/dkim"
)

type Service interface {
	Evaluate(ctx context.Context, eval *InboundEvaluation) (*InboundEvaluation, error)
	VerifyRecipient(ctx context.Context, email string) (bool, error)
	RateLimiter() *MemoryRateLimiter
}

type service struct {
	db          *sql.DB
	dkimService dkim.Service
	verifier    RecipientVerifier
	limiter     *MemoryRateLimiter
}

func NewService(db *sql.DB, dkimService dkim.Service) Service {
	return &service{
		db:          db,
		dkimService: dkimService,
		verifier:    NewPostgresRecipientVerifier(db),
		limiter:     NewMemoryRateLimiter(RateLimitPolicy{}),
	}
}

func (s *service) RateLimiter() *MemoryRateLimiter {
	return s.limiter
}

func (s *service) VerifyRecipient(ctx context.Context, email string) (bool, error) {
	return s.verifier.VerifyRecipient(ctx, email)
}

func (s *service) Evaluate(ctx context.Context, eval *InboundEvaluation) (*InboundEvaluation, error) {
	eval.EvaluatedAt = time.Now().UTC()

	// 1. Recipient check
	if eval.Recipient != "" {
		ok, err := s.VerifyRecipient(ctx, eval.Recipient)
		if err != nil || !ok {
			return eval, ErrRecipientRejected
		}
	}

	// 2. Evaluate DMARC alignment
	dmarcVer := EvaluateDMARC(eval.HeaderFrom, eval.SPF, eval.DKIM, eval.DMARC.Policy)
	eval.DMARC = dmarcVer

	// 3. Evaluate unified security & spam verdict
	err := EvaluateInboundSecurity(eval)

	// 4. Inject standardized headers
	eval.AuthenticationResults = BuildAuthenticationResults(eval)
	eval.ReceivedSPF = BuildReceivedSPF(eval)

	return eval, err
}
