package postfix

import "errors"

var (
	ErrDomainNotFound   = errors.New("domain not found or inactive in postfix lookup")
	ErrMailboxNotFound  = errors.New("mailbox not found, inactive, or not ready for postfix delivery")
	ErrAliasNotFound    = errors.New("alias not found")
	ErrInvalidRecipient = errors.New("invalid recipient address")
	ErrPostfixCheckFail = errors.New("postfix configuration validation check failed")
)

type LookupResult struct {
	Query       string `json:"query"`
	Found       bool   `json:"found"`
	Destination string `json:"destination,omitempty"`
}

type MailboxTransportInfo struct {
	Email              string `json:"email"`
	Domain             string `json:"domain"`
	Status             string `json:"status"`
	ProvisioningStatus string `json:"provisioning_status"`
}
