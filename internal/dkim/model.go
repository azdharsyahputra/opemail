package dkim

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

var (
	ErrDKIMKeyNotFound      = errors.New("dkim key not found")
	ErrDKIMKeyExists        = errors.New("dkim key for domain and selector already exists")
	ErrInvalidSelector      = errors.New("invalid dkim selector format")
	ErrInvalidAlgorithm     = errors.New("unsupported algorithm: only rsa-sha256 is supported")
	ErrInvalidKeyBits       = errors.New("unsupported key size: only 2048 bits is supported")
	ErrPrivateKeyNotFound   = errors.New("private key file not found in keystore")
	ErrKeyMismatch          = errors.New("dns public key does not match local private key")
	ErrDNSVerificationFailed = errors.New("dkim dns txt record verification failed")
	ErrPolicyNotFound       = errors.New("domain mail policy not found")
)

type DKIMStatus string

const (
	StatusPending DKIMStatus = "pending"
	StatusActive  DKIMStatus = "active"
	StatusRevoked DKIMStatus = "revoked"
)

type DKIMKey struct {
	ID          uuid.UUID  `json:"id"`
	DomainID    uuid.UUID  `json:"domain_id"`
	Domain      string     `json:"domain,omitempty"`
	Selector    string     `json:"selector"`
	Algorithm   string     `json:"algorithm"`
	KeyBits     int        `json:"key_bits"`
	Status      DKIMStatus `json:"status"`
	CreatedAt   time.Time  `json:"created_at"`
	ActivatedAt *time.Time `json:"activated_at,omitempty"`
	RevokedAt   *time.Time `json:"revoked_at,omitempty"`
}

type DomainMailPolicy struct {
	DomainID          uuid.UUID `json:"domain_id"`
	Domain            string    `json:"domain,omitempty"`
	SPFPolicy         string    `json:"spf_policy"`
	DMARCPolicy       string    `json:"dmarc_policy"`
	SpamThreshold     float64   `json:"spam_threshold"`
	RejectThreshold   float64   `json:"reject_threshold"`
	QuarantineEnabled bool      `json:"quarantine_enabled"`
	MaxMessageSize    int64     `json:"max_message_size"`
	RBLPolicy         string    `json:"rbl_policy"`
	RDNSPolicy        string    `json:"rdns_policy"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}


type Keypair struct {
	PrivateKeyPEM []byte `json:"-"`
	PublicKeyPEM  []byte `json:"public_key_pem"`
	PublicKeyDNS  string `json:"public_key_dns"` // Base64 DER without headers
}

type DNSRecord struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value string `json:"value"`
}

type VerificationResult struct {
	Domain           string `json:"domain"`
	Selector         string `json:"selector"`
	DNSRecordFound   bool   `json:"dns_record_found"`
	DNSValue         string `json:"dns_value,omitempty"`
	PublicKeyValid   bool   `json:"public_key_valid"`
	KeyMatches       bool   `json:"key_matches"`
	Status           string `json:"status"` // VERIFIED, NOT READY, MISMATCH
	Message          string `json:"message,omitempty"`
}
