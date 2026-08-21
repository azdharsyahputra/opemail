package handler

import (
	"net/http"

	"github.com/azdharsyahputra/openmail/internal/api/response"
	"github.com/azdharsyahputra/openmail/internal/quota"
	"github.com/go-chi/chi/v5"
)

type QuotaHandler struct {
	quotaService quota.Service
}

func NewQuotaHandler(quotaSvc quota.Service) *QuotaHandler {
	return &QuotaHandler{quotaService: quotaSvc}
}

func (h *QuotaHandler) Get(w http.ResponseWriter, r *http.Request) {
	email := chi.URLParam(r, "email")
	q, err := h.quotaService.GetQuota(r.Context(), email)
	if err != nil {
		response.Error(w, r, http.StatusNotFound, response.ErrCodeMailboxNotFound, "mailbox quota not found", err.Error())
		return
	}

	response.JSON(w, http.StatusOK, map[string]interface{}{
		"email":        q.Email,
		"limit":        q.QuotaBytes,
		"used":         q.UsedBytes,
		"percentage":   q.UsagePercent,
		"status":       q.Status,
		"is_exceeded":  q.IsExceeded,
	})
}

func (h *QuotaHandler) Reconcile(w http.ResponseWriter, r *http.Request) {
	email := chi.URLParam(r, "email")
	q, err := h.quotaService.Reconcile(r.Context(), email)
	if err != nil {
		response.Error(w, r, http.StatusInternalServerError, response.ErrCodeInternal, "failed to reconcile quota", err.Error())
		return
	}

	response.JSON(w, http.StatusOK, map[string]interface{}{
		"email":        q.Email,
		"limit":        q.QuotaBytes,
		"used":         q.UsedBytes,
		"percentage":   q.UsagePercent,
		"status":       q.Status,
		"is_exceeded":  q.IsExceeded,
	})
}
