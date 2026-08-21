package token

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

var (
	ErrTokenNotFound = errors.New("token not found")
	ErrTokenExpired  = errors.New("token has expired")
	ErrTokenRevoked  = errors.New("token has been revoked")
	ErrInvalidToken  = errors.New("invalid token format")
)

type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"` // seconds
}

type Claims struct {
	TokenID uuid.UUID
	UserID  *uuid.UUID
	Email   string
	Role    string
}

type Manager interface {
	IssueTokenPair(ctx context.Context, userID *uuid.UUID, email, role string) (*TokenPair, error)
	ValidateAccessToken(ctx context.Context, rawToken string) (*Claims, error)
	RefreshTokens(ctx context.Context, rawRefreshToken string) (*TokenPair, error)
	RevokeToken(ctx context.Context, rawToken string) error
	RevokeAllForEmail(ctx context.Context, email string) error
}

type manager struct {
	repo               Repository
	accessTokenTTL     time.Duration
	refreshTokenTTL    time.Duration
}

func NewManager(repo Repository) Manager {
	return &manager{
		repo:            repo,
		accessTokenTTL:  15 * time.Minute,
		refreshTokenTTL: 30 * 24 * time.Hour,
	}
}

func hashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func generateRandomToken(prefix string) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return fmt.Sprintf("%s%s", prefix, hex.EncodeToString(b)), nil
}

func (m *manager) IssueTokenPair(ctx context.Context, userID *uuid.UUID, email, role string) (*TokenPair, error) {
	if role == "" {
		role = "user"
	}

	// 1. Generate access token
	rawAT, err := generateRandomToken("mo_at_")
	if err != nil {
		return nil, fmt.Errorf("generate access token: %w", err)
	}

	atRecord := &APIToken{
		ID:        uuid.New(),
		UserID:    userID,
		Email:     email,
		Role:      role,
		TokenHash: hashToken(rawAT),
		TokenType: "access",
		ExpiresAt: time.Now().UTC().Add(m.accessTokenTTL),
		CreatedAt: time.Now().UTC(),
	}
	if err := m.repo.Store(ctx, atRecord); err != nil {
		return nil, fmt.Errorf("store access token: %w", err)
	}

	// 2. Generate refresh token
	rawRT, err := generateRandomToken("mo_rt_")
	if err != nil {
		return nil, fmt.Errorf("generate refresh token: %w", err)
	}

	rtRecord := &APIToken{
		ID:        uuid.New(),
		UserID:    userID,
		Email:     email,
		Role:      role,
		TokenHash: hashToken(rawRT),
		TokenType: "refresh",
		ExpiresAt: time.Now().UTC().Add(m.refreshTokenTTL),
		CreatedAt: time.Now().UTC(),
	}
	if err := m.repo.Store(ctx, rtRecord); err != nil {
		return nil, fmt.Errorf("store refresh token: %w", err)
	}

	return &TokenPair{
		AccessToken:  rawAT,
		RefreshToken: rawRT,
		TokenType:    "Bearer",
		ExpiresIn:    int(m.accessTokenTTL.Seconds()),
	}, nil
}

func (m *manager) ValidateAccessToken(ctx context.Context, rawToken string) (*Claims, error) {
	if rawToken == "" {
		return nil, ErrInvalidToken
	}

	tokenHash := hashToken(rawToken)
	tok, err := m.repo.GetByHash(ctx, tokenHash)
	if err != nil {
		return nil, ErrTokenNotFound
	}

	if tok.TokenType != "access" {
		return nil, ErrInvalidToken
	}

	if tok.RevokedAt != nil {
		return nil, ErrTokenRevoked
	}

	if time.Now().UTC().After(tok.ExpiresAt) {
		return nil, ErrTokenExpired
	}

	_ = m.repo.UpdateLastUsed(ctx, tok.ID)

	return &Claims{
		TokenID: tok.ID,
		UserID:  tok.UserID,
		Email:   tok.Email,
		Role:    tok.Role,
	}, nil
}

func (m *manager) RefreshTokens(ctx context.Context, rawRefreshToken string) (*TokenPair, error) {
	if rawRefreshToken == "" {
		return nil, ErrInvalidToken
	}

	tokenHash := hashToken(rawRefreshToken)
	tok, err := m.repo.GetByHash(ctx, tokenHash)
	if err != nil {
		return nil, ErrTokenNotFound
	}

	if tok.TokenType != "refresh" {
		return nil, ErrInvalidToken
	}

	if tok.RevokedAt != nil {
		// Security Alert: Revoked token reuse detected! Revoke entire token family for this account.
		_ = m.repo.RevokeAllForEmail(ctx, tok.Email)
		return nil, ErrTokenRevoked
	}


	if time.Now().UTC().After(tok.ExpiresAt) {
		return nil, ErrTokenExpired
	}

	// Revoke the old refresh token (one-time rotation)
	_ = m.repo.RevokeByHash(ctx, tokenHash)

	// Issue new token pair
	return m.IssueTokenPair(ctx, tok.UserID, tok.Email, tok.Role)
}

func (m *manager) RevokeToken(ctx context.Context, rawToken string) error {
	if rawToken == "" {
		return nil
	}
	return m.repo.RevokeByHash(ctx, hashToken(rawToken))
}

func (m *manager) RevokeAllForEmail(ctx context.Context, email string) error {
	return m.repo.RevokeAllForEmail(ctx, email)
}
