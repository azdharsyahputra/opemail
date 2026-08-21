package response

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/azdharsyahputra/openmail/internal/api/middleware"
)

type APIError struct {
	Code      string      `json:"code"`
	Message   string      `json:"message"`
	RequestID string      `json:"request_id,omitempty"`
	Details   interface{} `json:"details,omitempty"`
}

type ErrorResponse struct {
	Error APIError `json:"error"`
}

const (
	ErrCodeUnauthorized        = "AUTH_UNAUTHORIZED"
	ErrCodeInvalidCredentials  = "AUTH_INVALID_CREDENTIALS"
	ErrCodeAccountSuspended    = "AUTH_ACCOUNT_SUSPENDED"
	ErrCodeAccountDisabled     = "AUTH_ACCOUNT_DISABLED"
	ErrCodeForbidden           = "FORBIDDEN"
	ErrCodeNotFound            = "NOT_FOUND"
	ErrCodeDomainNotFound      = "DOMAIN_NOT_FOUND"
	ErrCodeDomainAlreadyExists = "DOMAIN_ALREADY_EXISTS"
	ErrCodeMailboxNotFound     = "MAILBOX_NOT_FOUND"
	ErrCodeMailboxExists       = "MAILBOX_ALREADY_EXISTS"
	ErrCodeMailboxSuspended    = "MAILBOX_SUSPENDED"
	ErrCodeMailboxNotReady     = "MAILBOX_NOT_READY"
	ErrCodeAliasNotFound       = "ALIAS_NOT_FOUND"
	ErrCodeAliasExists         = "ALIAS_ALREADY_EXISTS"
	ErrCodeLDAPUnavailable     = "LDAP_UNAVAILABLE"
	ErrCodeLDAPAuthFailed      = "LDAP_AUTH_FAILED"
	ErrCodeLDAPSyncFailed      = "LDAP_SYNC_FAILED"
	ErrCodeQueueMessageNotFound= "QUEUE_MESSAGE_NOT_FOUND"
	ErrCodeQueueOpFailed       = "QUEUE_OPERATION_FAILED"
	ErrCodeQuotaExceeded       = "QUOTA_EXCEEDED"
	ErrCodeRateLimited         = "RATE_LIMITED"
	ErrCodeValidationError     = "VALIDATION_ERROR"
	ErrCodeInternal            = "INTERNAL_ERROR"
)

type PaginationRequest struct {
	Page   int `json:"page"`
	Limit  int `json:"limit"`
	Offset int `json:"offset"`
}

type PaginationResponse struct {
	Total      int    `json:"total"`
	Page       int    `json:"page,omitempty"`
	Limit      int    `json:"limit"`
	HasMore    bool   `json:"has_more"`
	NextCursor string `json:"next_cursor,omitempty"`
}

type DataListResponse struct {
	Data       interface{}        `json:"data"`
	Pagination PaginationResponse `json:"pagination"`
}

type DataItemResponse struct {
	Data interface{} `json:"data"`
}

func JSON(w http.ResponseWriter, statusCode int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(statusCode)
	if payload != nil {
		_ = json.NewEncoder(w).Encode(payload)
	}
}

func GetRequestID(ctx context.Context) string {
	if val := ctx.Value(middleware.RequestIDKey); val != nil {
		if s, ok := val.(string); ok {
			return s
		}
	}
	return ""
}

func Error(w http.ResponseWriter, r *http.Request, statusCode int, code, message string, details interface{}) {
	reqID := GetRequestID(r.Context())
	resp := ErrorResponse{
		Error: APIError{
			Code:      code,
			Message:   message,
			RequestID: reqID,
			Details:   details,
		},
	}
	JSON(w, statusCode, resp)
}
