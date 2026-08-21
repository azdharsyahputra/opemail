package handler

import (
	"net/http"
	"strconv"

	"github.com/azdharsyahputra/openmail/internal/api/response"
	"github.com/azdharsyahputra/openmail/internal/audit"
)

type AuditHandler struct {
	auditService audit.Service
}

func NewAuditHandler(auditSvc audit.Service) *AuditHandler {
	return &AuditHandler{auditService: auditSvc}
}

func (h *AuditHandler) List(w http.ResponseWriter, r *http.Request) {
	limitStr := r.URL.Query().Get("limit")
	limit := 50
	if parsed, err := strconv.Atoi(limitStr); err == nil && parsed > 0 && parsed <= 500 {
		limit = parsed
	}

	logs, err := h.auditService.ListAuditLogs(r.Context(), limit)
	if err != nil {
		response.Error(w, r, http.StatusInternalServerError, response.ErrCodeInternal, "failed to list audit logs", err.Error())
		return
	}

	response.JSON(w, http.StatusOK, response.DataListResponse{
		Data: logs,
		Pagination: response.PaginationResponse{
			Total: len(logs),
			Limit: limit,
		},
	})
}
