package inbound

import (
	"errors"
	"net"
	"time"
)

var (
	ErrRecipientRejected = errors.New("recipient address rejected: user unknown in virtual mailbox table")
	ErrDomainInactive    = errors.New("recipient domain is inactive")
	ErrMessageOversized  = errors.New("message size exceeds fixed maximum message size")
	ErrDMARCRejected     = errors.New("message rejected by domain dmarc policy")
	ErrMalwareDetected   = errors.New("message contains malware virus payload")
)

type AuthStatus string

const (
	AuthPass      AuthStatus = "pass"
	AuthFail      AuthStatus = "fail"
	AuthSoftFail  AuthStatus = "softfail"
	AuthNeutral   AuthStatus = "neutral"
	AuthNone      AuthStatus = "none"
	AuthTempError AuthStatus = "temperror"
	AuthPermError AuthStatus = "permerror"
)

type SpamAction string

const (
	ActionDeliver    SpamAction = "deliver"
	ActionJunk       SpamAction = "junk"
	ActionQuarantine SpamAction = "quarantine"
	ActionReject     SpamAction = "reject"
)

type SPFVerification struct {
	Status  AuthStatus `json:"status"`
	Domain  string     `json:"domain"`
	Scope   string     `json:"scope"`   // mfrom, helo
	Aligned bool       `json:"aligned"` // matches RFC5322 From domain
	Reason  string     `json:"reason,omitempty"`
}

type DKIMVerification struct {
	Status   AuthStatus `json:"status"`
	Domain   string     `json:"domain"`
	Selector string     `json:"selector"`
	Aligned  bool       `json:"aligned"` // matches RFC5322 From domain
	Reason   string     `json:"reason,omitempty"`
}

type DMARCVerification struct {
	Status      AuthStatus `json:"status"` // pass, fail, none
	Policy      string     `json:"policy"` // none, quarantine, reject
	SPFAligned  bool       `json:"spf_aligned"`
	DKIMAligned bool       `json:"dkim_aligned"`
	Action      SpamAction `json:"action"` // deliver, junk, quarantine, reject
	Reason      string     `json:"reason,omitempty"`
}

type ReputationReport struct {
	ClientIP     net.IP   `json:"client_ip"`
	PTRHostname  string   `json:"ptr_hostname,omitempty"`
	FCrDNSValid  bool     `json:"fcrdns_valid"`
	RBLLookups   []string `json:"rbl_lookups,omitempty"`
	RBLListed    bool     `json:"rbl_listed"`
	ReputationScore float64 `json:"reputation_score"`
}

type InboundEvaluation struct {
	AuthServID             string            `json:"auth_serv_id"` // e.g. mail.example.com
	ClientIP               net.IP            `json:"client_ip"`
	ClientHostname         string            `json:"client_hostname"`
	HELO                   string            `json:"helo"`
	MailFrom               string            `json:"mail_from"`
	HeaderFrom             string            `json:"header_from"`
	Recipient              string            `json:"recipient"`
	MessageSize            int64             `json:"message_size"`
	SPF                    SPFVerification   `json:"spf"`
	DKIM                   DKIMVerification  `json:"dkim"`
	DMARC                  DMARCVerification `json:"dmarc"`
	SpamScore              float64           `json:"spam_score"`
	SpamThreshold          float64           `json:"spam_threshold"`
	RejectThreshold        float64           `json:"reject_threshold"`
	IsSpam                 bool              `json:"is_spam"`
	AntivirusClean         bool              `json:"antivirus_clean"`
	VirusName              string            `json:"virus_name,omitempty"`
	FinalAction            SpamAction        `json:"final_action"`
	AuthenticationResults  string            `json:"authentication_results"`
	ReceivedSPF            string            `json:"received_spf"`
	EvaluatedAt            time.Time         `json:"evaluated_at"`
}
