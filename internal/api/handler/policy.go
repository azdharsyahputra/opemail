package handler

import (
	"encoding/json"
	"net/http"

	"github.com/azdharsyahputra/openmail/internal/api/response"
	"github.com/azdharsyahputra/openmail/internal/dkim"
	"github.com/go-chi/chi/v5"
)

type PolicyHandler struct {
	dkimService dkim.Service
}

func NewPolicyHandler(dkimSvc dkim.Service) *PolicyHandler {
	return &PolicyHandler{dkimService: dkimSvc}
}

type UpdatePolicyRequest struct {
	SPFPolicy   string `json:"spf_policy,omitempty"`
	DMARCPolicy string `json:"dmarc_policy,omitempty"`
}

func (h *PolicyHandler) Get(w http.ResponseWriter, r *http.Request) {
	domName := chi.URLParam(r, "domain")
	pol, err := h.dkimService.GetPolicy(r.Context(), domName)
	if err != nil {
		response.Error(w, r, http.StatusNotFound, response.ErrCodeDomainNotFound, "domain policy not found", err.Error())
		return
	}

	response.JSON(w, http.StatusOK, pol)
}

func (h *PolicyHandler) Update(w http.ResponseWriter, r *http.Request) {
	domName := chi.URLParam(r, "domain")
	var req UpdatePolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.ErrCodeValidationError, "malformed request payload", err.Error())
		return
	}

	if req.SPFPolicy != "" {
		if err := h.dkimService.SetSPFPolicy(r.Context(), domName, req.SPFPolicy); err != nil {
			response.Error(w, r, http.StatusBadRequest, response.ErrCodeValidationError, "invalid spf policy", err.Error())
			return
		}
	}

	if req.DMARCPolicy != "" {
		if err := h.dkimService.SetDMARCPolicy(r.Context(), domName, req.DMARCPolicy); err != nil {
			response.Error(w, r, http.StatusBadRequest, response.ErrCodeValidationError, "invalid dmarc policy", err.Error())
			return
		}
	}

	pol, _ := h.dkimService.GetPolicy(r.Context(), domName)
	response.JSON(w, http.StatusOK, pol)
}
