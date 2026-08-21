package bounce

type BounceType string

const (
	TypePermanent BounceType = "permanent" // 5xx
	TypeTemporary BounceType = "temporary" // 4xx
	TypeUnknown   BounceType = "unknown"
)

type BounceCategory string

const (
	CategoryRecipientUnknown  BounceCategory = "recipient_unknown"   // 5.1.1
	CategoryDomainUnknown     BounceCategory = "domain_unknown"      // 5.1.2
	CategoryMailboxFull       BounceCategory = "mailbox_full"        // 5.2.2 / 4.2.2
	CategoryMessageOversized  BounceCategory = "message_oversized"   // 5.3.4
	CategoryPolicyRejection   BounceCategory = "policy_rejection"    // 5.7.1
	CategorySpamRejection     BounceCategory = "spam_rejection"      // 5.7.0 / 5.7.28
	CategoryTLSFailure        BounceCategory = "tls_failure"         // 5.7.4 / 5.7.10
	CategoryConnectionFailure BounceCategory = "connection_failure"  // 4.4.1 / 4.4.2
	CategoryTemporaryFailure  BounceCategory = "temporary_failure"   // 4.7.1 / 4.0.0
	CategorySystemError       BounceCategory = "system_error"        // 5.3.0
	CategoryUnknown           BounceCategory = "unknown"
)

type BounceReport struct {
	Type              BounceType     `json:"type"`
	Category          BounceCategory `json:"category"`
	ReplyCode         int            `json:"reply_code"`
	EnhancedCode      string         `json:"enhanced_code"`
	DiagnosticCode    string         `json:"diagnostic_code"`
	OriginalRecipient string         `json:"original_recipient,omitempty"`
	RemoteMTA         string         `json:"remote_mta,omitempty"`
	IsHardBounce      bool           `json:"is_hard_bounce"`
}
