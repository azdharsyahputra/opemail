package handler

import (
	"encoding/json"
	"net/http"

	"github.com/azdharsyahputra/openmail/internal/api/response"
	"github.com/azdharsyahputra/openmail/internal/quota"
)

type QuotaHandler struct {
	quotaService quota.Service
}

func NewQuotaHandler(quotaSvc quota.Service) *QuotaHandler {
	return &QuotaHandler{quotaService: quotaSvc}
}

type UpdateQuotaRequest struct {
	QuotaBytes int64 `json:"quota_bytes"`
}

func (h *QuotaHandler) Get(w http.ResponseWriter, r *http.Request) {
	email := parseEmailParam(r, "email")
	q, err := h.quotaService.GetQuota(r.Context(), email)
	if err != nil {
		response.Error(w, r, http.StatusNotFound, response.ErrCodeMailboxNotFound, "mailbox quota not found", err.Error())
		return
	}

	response.JSON(w, http.StatusOK, map[string]interface{}{
		"email":       q.Email,
		"limit":       q.QuotaBytes,
		"used":        q.UsedBytes,
		"percentage":  q.UsagePercent,
		"status":      q.Status,
		"is_exceeded": q.IsExceeded,
	})
}

func (h *QuotaHandler) Update(w http.ResponseWriter, r *http.Request) {
	email := parseEmailParam(r, "email")
	var req UpdateQuotaRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.ErrCodeValidationError, "malformed request payload", err.Error())
		return
	}

	if req.QuotaBytes <= 0 {
		response.Error(w, r, http.StatusBadRequest, response.ErrCodeValidationError, "quota_bytes must be a positive integer", nil)
		return
	}

	q, err := h.quotaService.UpdateQuota(r.Context(), email, req.QuotaBytes)
	if err != nil {
		response.Error(w, r, http.StatusInternalServerError, response.ErrCodeInternal, "failed to update mailbox quota", err.Error())
		return
	}

	response.JSON(w, http.StatusOK, map[string]interface{}{
		"email":       q.Email,
		"limit":       q.QuotaBytes,
		"used":        q.UsedBytes,
		"percentage":  q.UsagePercent,
		"status":      q.Status,
		"is_exceeded": q.IsExceeded,
	})
}

func (h *QuotaHandler) Reconcile(w http.ResponseWriter, r *http.Request) {
	email := parseEmailParam(r, "email")
	q, err := h.quotaService.Reconcile(r.Context(), email)
	if err != nil {
		response.Error(w, r, http.StatusInternalServerError, response.ErrCodeInternal, "failed to reconcile quota", err.Error())
		return
	}

	response.JSON(w, http.StatusOK, map[string]interface{}{
		"email":       q.Email,
		"limit":       q.QuotaBytes,
		"used":        q.UsedBytes,
		"percentage":  q.UsagePercent,
		"status":      q.Status,
		"is_exceeded": q.IsExceeded,
	})
}
