package mailbox

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/mail"
	"strings"
	"time"

	"github.com/azdharsyahputra/openmail/internal/domain"
	"github.com/azdharsyahputra/openmail/internal/provisioning"
	"github.com/google/uuid"
	"golang.org/x/crypto/argon2"
)

type Argon2Params struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

var DefaultArgon2Params = Argon2Params{
	Memory:      64 * 1024,
	Iterations:  1,
	Parallelism: 4,
	SaltLength:  16,
	KeyLength:   32,
}

type Service interface {
	Create(ctx context.Context, email, password string, quotaBytes int64) (*Mailbox, error)
	Provision(ctx context.Context, email string) (*Mailbox, bool, error)
	Doctor(ctx context.Context, email string) (*provisioning.DoctorReport, error)
	GetByEmail(ctx context.Context, email string) (*Mailbox, error)
	List(ctx context.Context) ([]*Mailbox, error)
	Delete(ctx context.Context, email string) error
	VerifyPassword(password, encodedHash string) (bool, error)
}

type service struct {
	mailboxRepo Repository
	domainRepo  domain.Repository
	provisioner provisioning.Provisioner
}

func NewService(mailboxRepo Repository, domainRepo domain.Repository, provisioner provisioning.Provisioner) Service {
	return &service{
		mailboxRepo: mailboxRepo,
		domainRepo:  domainRepo,
		provisioner: provisioner,
	}
}

func (s *service) Create(ctx context.Context, email, password string, quotaBytes int64) (*Mailbox, error) {
	email = strings.TrimSpace(strings.ToLower(email))

	// 1. Validate email address
	if !isValidEmail(email) {
		return nil, ErrInvalidEmail
	}

	// 2. Validate password
	if len(password) < 8 {
		return nil, ErrInvalidPassword
	}

	// 3. Extract domain part
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return nil, ErrInvalidEmail
	}
	domainName := parts[1]

	// 4. Resolve domain existence
	dom, err := s.domainRepo.GetByName(ctx, domainName)
	if err != nil {
		if errors.Is(err, domain.ErrDomainNotFound) {
			return nil, ErrDomainNotFound
		}
		return nil, fmt.Errorf("error resolving domain: %w", err)
	}

	// 5. Check if email already exists
	existing, err := s.mailboxRepo.GetByEmail(ctx, email)
	if err == nil && existing != nil {
		return nil, ErrMailboxExists
	}
	if err != nil && !errors.Is(err, ErrMailboxNotFound) {
		return nil, err
	}

	// Default quota: 1GB (1073741824 bytes)
	if quotaBytes <= 0 {
		quotaBytes = 1073741824
	}

	// 6. Hash password with Argon2id
	hashedPassword, err := HashPassword(password, DefaultArgon2Params)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	now := time.Now().UTC()
	m := &Mailbox{
		ID:                 uuid.New(),
		DomainID:           dom.ID,
		Email:              email,
		PasswordHash:       hashedPassword,
		QuotaBytes:         quotaBytes,
		Status:             "active",
		ProvisioningStatus: ProvisioningPending,
		CreatedAt:          now,
		UpdatedAt:          now,
		DomainName:         dom.Name,
	}

	// 7. Save mailbox to DB
	if err := s.mailboxRepo.Create(ctx, m); err != nil {
		return nil, err
	}

	// 8. Provision mailbox via Provisioner layer (if provisioner configured)
	if s.provisioner != nil {
		_ = s.mailboxRepo.UpdateProvisioningStatus(ctx, m.ID, ProvisioningInProgress)

		provErr := s.provisioner.Provision(ctx, provisioning.Mailbox{
			ID:         m.ID.String(),
			Email:      m.Email,
			Domain:     dom.Name,
			QuotaBytes: m.QuotaBytes,
		})

		if provErr != nil {
			// Mark as failed in DB and compensate/clean up if needed
			_ = s.mailboxRepo.UpdateProvisioningStatus(ctx, m.ID, ProvisioningFailed)
			return nil, fmt.Errorf("mailbox provisioning failed: %w", provErr)
		}

		m.ProvisioningStatus = ProvisioningReady
		_ = s.mailboxRepo.UpdateProvisioningStatus(ctx, m.ID, ProvisioningReady)
	}

	return m, nil
}

func (s *service) Provision(ctx context.Context, email string) (*Mailbox, bool, error) {
	email = strings.TrimSpace(strings.ToLower(email))
	mb, err := s.mailboxRepo.GetByEmail(ctx, email)
	if err != nil {
		return nil, false, err
	}

	if mb.ProvisioningStatus == ProvisioningReady {
		return mb, true, nil
	}

	if s.provisioner == nil {
		return mb, false, fmt.Errorf("provisioner not configured")
	}

	_ = s.mailboxRepo.UpdateProvisioningStatus(ctx, mb.ID, ProvisioningInProgress)

	err = s.provisioner.Provision(ctx, provisioning.Mailbox{
		ID:         mb.ID.String(),
		Email:      mb.Email,
		Domain:     mb.DomainName,
		QuotaBytes: mb.QuotaBytes,
	})
	if err != nil {
		_ = s.mailboxRepo.UpdateProvisioningStatus(ctx, mb.ID, ProvisioningFailed)
		return nil, false, fmt.Errorf("failed to provision mailbox: %w", err)
	}

	mb.ProvisioningStatus = ProvisioningReady
	_ = s.mailboxRepo.UpdateProvisioningStatus(ctx, mb.ID, ProvisioningReady)

	return mb, false, nil
}

func (s *service) Doctor(ctx context.Context, email string) (*provisioning.DoctorReport, error) {
	email = strings.TrimSpace(strings.ToLower(email))
	mb, err := s.mailboxRepo.GetByEmail(ctx, email)
	if err != nil {
		return nil, err
	}

	if s.provisioner == nil {
		return nil, fmt.Errorf("provisioner not configured")
	}

	report, err := s.provisioner.Inspect(ctx, provisioning.Mailbox{
		ID:         mb.ID.String(),
		Email:      mb.Email,
		Domain:     mb.DomainName,
		QuotaBytes: mb.QuotaBytes,
	})
	if err != nil {
		return nil, err
	}

	report.Status = mb.Status
	report.ProvisionStatus = mb.ProvisioningStatus

	if mb.ProvisioningStatus != ProvisioningReady || mb.Status != "active" {
		report.Healthy = false
	}

	return report, nil
}

func (s *service) GetByEmail(ctx context.Context, email string) (*Mailbox, error) {
	email = strings.TrimSpace(strings.ToLower(email))
	if email == "" {
		return nil, ErrInvalidEmail
	}
	return s.mailboxRepo.GetByEmail(ctx, email)
}

func (s *service) List(ctx context.Context) ([]*Mailbox, error) {
	return s.mailboxRepo.List(ctx)
}

func (s *service) Delete(ctx context.Context, email string) error {
	email = strings.TrimSpace(strings.ToLower(email))
	if email == "" {
		return ErrInvalidEmail
	}

	mb, err := s.mailboxRepo.GetByEmail(ctx, email)
	if err != nil {
		return err
	}

	// 1. Mark as deprovisioning / deleting
	_ = s.mailboxRepo.UpdateStatus(ctx, mb.ID, "deleting")
	_ = s.mailboxRepo.UpdateProvisioningStatus(ctx, mb.ID, ProvisioningDeprovisioning)

	// 2. Clean up filesystem
	if s.provisioner != nil {
		_ = s.provisioner.Deprovision(ctx, provisioning.Mailbox{
			ID:     mb.ID.String(),
			Email:  mb.Email,
			Domain: mb.DomainName,
		})
	}

	// 3. Delete from DB
	return s.mailboxRepo.Delete(ctx, email)
}

func (s *service) VerifyPassword(password, encodedHash string) (bool, error) {
	return VerifyPassword(password, encodedHash)
}

func isValidEmail(email string) bool {
	if len(email) == 0 || len(email) > 254 {
		return false
	}
	_, err := mail.ParseAddress(email)
	if err != nil {
		return false
	}
	parts := strings.Split(email, "@")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return false
	}
	return true
}

func HashPassword(password string, p Argon2Params) (string, error) {
	salt := make([]byte, p.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	hash := argon2.IDKey([]byte(password), salt, p.Iterations, p.Memory, p.Parallelism, p.KeyLength)

	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	encodedHash := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, p.Memory, p.Iterations, p.Parallelism, b64Salt, b64Hash)

	return encodedHash, nil
}

func VerifyPassword(password, encodedHash string) (bool, error) {
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 {
		return false, errors.New("invalid encoded hash format")
	}

	if parts[1] != "argon2id" {
		return false, errors.New("incompatible hash algorithm")
	}

	var version int
	_, err := fmt.Sscanf(parts[2], "v=%d", &version)
	if err != nil {
		return false, err
	}
	if version != argon2.Version {
		return false, errors.New("incompatible argon2 version")
	}

	var memory, iterations uint32
	var parallelism uint8
	_, err = fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &iterations, &parallelism)
	if err != nil {
		return false, err
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, err
	}

	decodedHash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, err
	}

	keyLength := uint32(len(decodedHash))
	otherHash := argon2.IDKey([]byte(password), salt, iterations, memory, parallelism, keyLength)

	if subtle.ConstantTimeCompare(decodedHash, otherHash) == 1 {
		return true, nil
	}
	return false, nil
}
