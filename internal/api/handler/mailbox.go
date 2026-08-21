package handler

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/azdharsyahputra/openmail/internal/api/response"
	"github.com/azdharsyahputra/openmail/internal/audit"
	"github.com/azdharsyahputra/openmail/internal/mailbox"
	"github.com/go-chi/chi/v5"
)

type MailboxHandler struct {
	mailboxService mailbox.Service
	auditService   audit.Service
}

func NewMailboxHandler(mbSvc mailbox.Service, auditSvc audit.Service) *MailboxHandler {
	return &MailboxHandler{
		mailboxService: mbSvc,
		auditService:   auditSvc,
	}
}

type CreateMailboxRequest struct {
	Email      string `json:"email"`
	Password   string `json:"password"`
	QuotaBytes int64  `json:"quota_bytes"`
}

type SetPasswordRequest struct {
	Password string `json:"password"`
}

func (h *MailboxHandler) List(w http.ResponseWriter, r *http.Request) {
	mailboxes, err := h.mailboxService.List(r.Context())
	if err != nil {
		response.Error(w, r, http.StatusInternalServerError, response.ErrCodeInternal, "failed to list mailboxes", err.Error())
		return
	}

	response.JSON(w, http.StatusOK, response.DataListResponse{
		Data: mailboxes,
		Pagination: response.PaginationResponse{
			Total: len(mailboxes),
			Limit: len(mailboxes),
		},
	})
}

func (h *MailboxHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req CreateMailboxRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.ErrCodeValidationError, "malformed request payload", err.Error())
		return
	}

	req.Email = strings.TrimSpace(strings.ToLower(req.Email))
	if req.Email == "" || req.Password == "" {
		response.Error(w, r, http.StatusBadRequest, response.ErrCodeValidationError, "email and password are required", nil)
		return
	}

	if req.QuotaBytes <= 0 {
		req.QuotaBytes = 1073741824 // 1GB default
	}

	mb, err := h.mailboxService.Create(r.Context(), req.Email, req.Password, req.QuotaBytes)
	if err != nil {
		if err == mailbox.ErrMailboxExists {
			response.Error(w, r, http.StatusConflict, response.ErrCodeMailboxExists, "mailbox already exists", nil)
			return
		}
		if err == mailbox.ErrInvalidEmail || err == mailbox.ErrInvalidPassword {
			response.Error(w, r, http.StatusBadRequest, response.ErrCodeValidationError, err.Error(), nil)
			return
		}
		response.Error(w, r, http.StatusInternalServerError, response.ErrCodeInternal, "failed to create mailbox", err.Error())
		return
	}

	// Trigger initial provisioning
	_, _, _ = h.mailboxService.Provision(r.Context(), req.Email)

	if h.auditService != nil {
		_ = h.auditService.RecordAudit(r.Context(), "api", nil, "mailbox.create", "mailbox", &mb.ID, map[string]string{"email": mb.Email})
	}

	response.JSON(w, http.StatusCreated, mb)
}

func (h *MailboxHandler) Get(w http.ResponseWriter, r *http.Request) {
	email := chi.URLParam(r, "email")
	mb, err := h.mailboxService.GetByEmail(r.Context(), email)
	if err != nil {
		response.Error(w, r, http.StatusNotFound, response.ErrCodeMailboxNotFound, "mailbox not found", nil)
		return
	}

	response.JSON(w, http.StatusOK, mb)
}

func (h *MailboxHandler) Delete(w http.ResponseWriter, r *http.Request) {
	email := chi.URLParam(r, "email")
	mb, _ := h.mailboxService.GetByEmail(r.Context(), email)

	err := h.mailboxService.Delete(r.Context(), email)
	if err != nil {
		if err == mailbox.ErrMailboxNotFound {
			response.Error(w, r, http.StatusNotFound, response.ErrCodeMailboxNotFound, "mailbox not found", nil)
			return
		}
		response.Error(w, r, http.StatusInternalServerError, response.ErrCodeInternal, "failed to delete mailbox", err.Error())
		return
	}

	if h.auditService != nil {
		var mbID *string
		if mb != nil {
			idStr := mb.ID.String()
			mbID = &idStr
		}
		_ = h.auditService.RecordAudit(r.Context(), "api", nil, "mailbox.delete", "mailbox", nil, map[string]interface{}{"email": email, "mailbox_id": mbID})
	}

	response.JSON(w, http.StatusOK, map[string]string{"message": "mailbox deleted successfully"})
}

func (h *MailboxHandler) Suspend(w http.ResponseWriter, r *http.Request) {
	email := chi.URLParam(r, "email")
	mb, err := h.mailboxService.GetByEmail(r.Context(), email)
	if err != nil {
		response.Error(w, r, http.StatusNotFound, response.ErrCodeMailboxNotFound, "mailbox not found", nil)
		return
	}

	if err := h.mailboxService.Suspend(r.Context(), mb.ID); err != nil {
		response.Error(w, r, http.StatusInternalServerError, response.ErrCodeInternal, "failed to suspend mailbox", err.Error())
		return
	}

	if h.auditService != nil {
		_ = h.auditService.RecordAudit(r.Context(), "api", nil, "mailbox.suspend", "mailbox", &mb.ID, map[string]string{"email": mb.Email})
	}

	response.JSON(w, http.StatusOK, map[string]string{"message": "mailbox suspended successfully"})
}

func (h *MailboxHandler) Resume(w http.ResponseWriter, r *http.Request) {
	email := chi.URLParam(r, "email")
	mb, err := h.mailboxService.GetByEmail(r.Context(), email)
	if err != nil {
		response.Error(w, r, http.StatusNotFound, response.ErrCodeMailboxNotFound, "mailbox not found", nil)
		return
	}

	if err := h.mailboxService.Resume(r.Context(), mb.ID); err != nil {
		response.Error(w, r, http.StatusInternalServerError, response.ErrCodeInternal, "failed to resume mailbox", err.Error())
		return
	}

	if h.auditService != nil {
		_ = h.auditService.RecordAudit(r.Context(), "api", nil, "mailbox.resume", "mailbox", &mb.ID, map[string]string{"email": mb.Email})
	}

	response.JSON(w, http.StatusOK, map[string]string{"message": "mailbox resumed successfully"})
}

func (h *MailboxHandler) Provision(w http.ResponseWriter, r *http.Request) {
	email := chi.URLParam(r, "email")
	mb, _, err := h.mailboxService.Provision(r.Context(), email)
	if err != nil {
		response.Error(w, r, http.StatusInternalServerError, response.ErrCodeInternal, "provisioning failed", err.Error())
		return
	}

	if h.auditService != nil {
		_ = h.auditService.RecordAudit(r.Context(), "api", nil, "mailbox.provision", "mailbox", &mb.ID, map[string]string{"email": mb.Email})
	}

	response.JSON(w, http.StatusOK, mb)
}

func (h *MailboxHandler) SetPassword(w http.ResponseWriter, r *http.Request) {
	email := chi.URLParam(r, "email")
	var req SetPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.ErrCodeValidationError, "malformed request payload", err.Error())
		return
	}

	if len(req.Password) < 8 {
		response.Error(w, r, http.StatusBadRequest, response.ErrCodeValidationError, "password must be at least 8 characters long", nil)
		return
	}

	if err := h.mailboxService.SetPassword(r.Context(), email, req.Password); err != nil {
		response.Error(w, r, http.StatusInternalServerError, response.ErrCodeInternal, "failed to set password", err.Error())
		return
	}

	if h.auditService != nil {
		// Secure audit: never log password
		_ = h.auditService.RecordAudit(r.Context(), "api", nil, "mailbox.password_change", "mailbox", nil, map[string]string{"email": email})
	}

	response.JSON(w, http.StatusOK, map[string]string{"message": "password updated successfully"})
}
