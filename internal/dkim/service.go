package dkim

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/azdharsyahputra/openmail/internal/domain"
	"github.com/google/uuid"
)


type Service interface {
	GenerateKey(ctx context.Context, domainName, selector string) (*DKIMKey, *Keypair, error)
	GetActiveKey(ctx context.Context, domainName string) (*DKIMKey, error)
	ListKeys(ctx context.Context, domainName string) ([]*DKIMKey, error)
	ActivateKey(ctx context.Context, domainName, selector string) error
	RevokeKey(ctx context.Context, domainName, selector string) error
	GetDNSRecord(ctx context.Context, domainName, selector string) (*DNSRecord, error)
	VerifyDNS(ctx context.Context, domainName, selector string, customLookup func(string) ([]string, error)) (*VerificationResult, error)
	GetPolicy(ctx context.Context, domainName string) (*DomainMailPolicy, error)
	SetSPFPolicy(ctx context.Context, domainName, policy string) error
	SetDMARCPolicy(ctx context.Context, domainName, policy string) error
	Keystore() Keystore
}

type service struct {
	repo       Repository
	domainRepo domain.Repository
	keystore   Keystore
}

func NewService(repo Repository, domainRepo domain.Repository, keystore Keystore) Service {
	return &service{
		repo:       repo,
		domainRepo: domainRepo,
		keystore:   keystore,
	}
}

func (s *service) Keystore() Keystore {
	return s.keystore
}

func (s *service) GenerateKey(ctx context.Context, domainName, selector string) (*DKIMKey, *Keypair, error) {
	domainName = strings.ToLower(strings.TrimSpace(domainName))
	selector = strings.ToLower(strings.TrimSpace(selector))
	if selector == "" {
		selector = "mailopen2026"
	}

	if err := ValidateSelector(selector); err != nil {
		return nil, nil, err
	}

	dom, err := s.domainRepo.GetByName(ctx, domainName)
	if err != nil {
		return nil, nil, fmt.Errorf("domain %s not found: %w", domainName, err)
	}

	// 1. Generate RSA-2048 keypair
	pair, err := GenerateRSAKeyPair(2048)
	if err != nil {
		return nil, nil, fmt.Errorf("generate keypair: %w", err)
	}

	// 2. Validate private key format before saving
	if _, err := ValidatePrivateKey(pair.PrivateKeyPEM); err != nil {
		return nil, nil, fmt.Errorf("validate key: %w", err)
	}

	// 3. Atomically store private key in filesystem keystore
	if _, err := s.keystore.StorePrivateKey(ctx, domainName, selector, pair.PrivateKeyPEM); err != nil {
		return nil, nil, fmt.Errorf("store private key: %w", err)
	}

	// 4. Create record in PostgreSQL
	dkimKey := &DKIMKey{
		ID:        uuid.New(),
		DomainID:  dom.ID,
		Domain:    domainName,
		Selector:  selector,
		Algorithm: "rsa-sha256",
		KeyBits:   2048,
		Status:    StatusPending, // Initially pending until verified
		CreatedAt: time.Now().UTC(),
	}

	if err := s.repo.CreateDKIMKey(ctx, dkimKey); err != nil {
		// Compensate cleanup on DB failure
		_ = s.keystore.DeletePrivateKey(ctx, domainName, selector)
		return nil, nil, err
	}

	return dkimKey, pair, nil
}

func (s *service) GetActiveKey(ctx context.Context, domainName string) (*DKIMKey, error) {
	dom, err := s.domainRepo.GetByName(ctx, domainName)
	if err != nil {
		return nil, err
	}
	return s.repo.GetActiveDKIMKey(ctx, dom.ID)
}

func (s *service) ListKeys(ctx context.Context, domainName string) ([]*DKIMKey, error) {
	dom, err := s.domainRepo.GetByName(ctx, domainName)
	if err != nil {
		return nil, err
	}
	return s.repo.ListDKIMKeysByDomain(ctx, dom.ID)
}

func (s *service) ActivateKey(ctx context.Context, domainName, selector string) error {
	dom, err := s.domainRepo.GetByName(ctx, domainName)
	if err != nil {
		return err
	}

	key, err := s.repo.GetDKIMKeyBySelector(ctx, dom.ID, selector)
	if err != nil {
		return err
	}

	if !s.keystore.HasPrivateKey(domainName, selector) {
		return ErrPrivateKeyNotFound
	}

	return s.repo.ActivateDKIMKey(ctx, key.ID)
}

func (s *service) RevokeKey(ctx context.Context, domainName, selector string) error {
	dom, err := s.domainRepo.GetByName(ctx, domainName)
	if err != nil {
		return err
	}

	key, err := s.repo.GetDKIMKeyBySelector(ctx, dom.ID, selector)
	if err != nil {
		return err
	}

	return s.repo.RevokeDKIMKey(ctx, key.ID)
}

func (s *service) GetDNSRecord(ctx context.Context, domainName, selector string) (*DNSRecord, error) {
	privBytes, err := s.keystore.GetPrivateKey(ctx, domainName, selector)
	if err != nil {
		return nil, err
	}

	privKey, err := ParseRSAPrivateKey(privBytes)
	if err != nil {
		return nil, err
	}

	pubDER, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal public key: %w", err)
	}

	pubBase64 := base64.StdEncoding.EncodeToString(pubDER)

	return &DNSRecord{
		Name:  BuildDNSName(domainName, selector),
		Type:  "TXT",
		Value: BuildDNSTXTValue(pubBase64),
	}, nil
}


func (s *service) VerifyDNS(ctx context.Context, domainName, selector string, customLookup func(string) ([]string, error)) (*VerificationResult, error) {
	domainName = strings.ToLower(strings.TrimSpace(domainName))
	selector = strings.ToLower(strings.TrimSpace(selector))

	result := &VerificationResult{
		Domain:   domainName,
		Selector: selector,
		Status:   "NOT READY",
	}

	// 1. Get private key from local keystore
	privBytes, err := s.keystore.GetPrivateKey(ctx, domainName, selector)
	if err != nil {
		result.Message = fmt.Sprintf("Local private key missing: %v", err)
		return result, ErrPrivateKeyNotFound
	}

	privKey, err := ParseRSAPrivateKey(privBytes)
	if err != nil {
		result.Message = fmt.Sprintf("Local private key corrupt: %v", err)
		return result, err
	}

	// 2. Perform DNS TXT query
	dnsName := BuildDNSName(domainName, selector)
	var records []string
	if customLookup != nil {
		records, err = customLookup(dnsName)
	} else {
		records, err = net.LookupTXT(dnsName)
	}

	if err != nil || len(records) == 0 {
		result.DNSRecordFound = false
		result.Message = fmt.Sprintf("DNS TXT record %s not found", dnsName)
		return result, nil
	}

	result.DNSRecordFound = true
	// Join multi-string TXT records if split
	combinedTXT := strings.Join(records, "")
	result.DNSValue = combinedTXT

	// 3. Parse DKIM TXT record
	_, pubKeyStr, err := ParseDNSTXTRecord(combinedTXT)
	if err != nil {
		result.PublicKeyValid = false
		result.Message = fmt.Sprintf("Invalid DKIM DNS record format: %v", err)
		return result, nil
	}

	pubKey, err := ParseRSAPublicKeyFromDNS(pubKeyStr)
	if err != nil {
		result.PublicKeyValid = false
		result.Message = fmt.Sprintf("Invalid RSA public key in DNS: %v", err)
		return result, nil
	}
	result.PublicKeyValid = true

	// 4. Verify Public Key matches Local Private Key
	if !ValidatePublicKeyMatch(privKey, pubKey) {
		result.KeyMatches = false
		result.Status = "MISMATCH"
		result.Message = "DNS public key does not match local private key"
		return result, ErrKeyMismatch
	}

	result.KeyMatches = true
	result.Status = "VERIFIED"
	result.Message = "DKIM DNS record is published and matches local key"

	return result, nil
}

func (s *service) GetPolicy(ctx context.Context, domainName string) (*DomainMailPolicy, error) {
	dom, err := s.domainRepo.GetByName(ctx, domainName)
	if err != nil {
		return nil, err
	}
	policy, err := s.repo.GetPolicy(ctx, dom.ID)
	if err != nil {
		if errors.Is(err, ErrPolicyNotFound) {
			serverIP := os.Getenv("SERVER_IP")
			if serverIP == "" {
				serverIP = "157.20.254.39"
			}
			// Return default initial policy
			return &DomainMailPolicy{
				DomainID:    dom.ID,
				Domain:      domainName,
				SPFPolicy:   fmt.Sprintf("v=spf1 a mx ip4:%s ~all", serverIP),
				DMARCPolicy: fmt.Sprintf("v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@%s", domainName),
			}, nil
		}
		return nil, err
	}
	return policy, nil
}

func (s *service) SetSPFPolicy(ctx context.Context, domainName, spfPolicy string) error {
	dom, err := s.domainRepo.GetByName(ctx, domainName)
	if err != nil {
		return err
	}

	current, err := s.GetPolicy(ctx, domainName)
	if err != nil {
		current = &DomainMailPolicy{
			DomainID:    dom.ID,
			DMARCPolicy: "v=DMARC1; p=none",
		}
	}
	current.SPFPolicy = spfPolicy
	return s.repo.UpsertPolicy(ctx, current)
}

func (s *service) SetDMARCPolicy(ctx context.Context, domainName, dmarcPolicy string) error {
	dom, err := s.domainRepo.GetByName(ctx, domainName)
	if err != nil {
		return err
	}

	current, err := s.GetPolicy(ctx, domainName)
	if err != nil {
		current = &DomainMailPolicy{
			DomainID:  dom.ID,
			SPFPolicy: "v=spf1 mx ~all",
		}
	}
	current.DMARCPolicy = dmarcPolicy
	return s.repo.UpsertPolicy(ctx, current)
}

