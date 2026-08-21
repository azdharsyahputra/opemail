package handler

import (
	"encoding/json"
	"net/http"

	"github.com/azdharsyahputra/openmail/internal/api/response"
	openmailtls "github.com/azdharsyahputra/openmail/internal/tls"
	"github.com/go-chi/chi/v5"
)

type TLSHandler struct {
	tlsService *openmailtls.Service
}

func NewTLSHandler(tlsSvc *openmailtls.Service) *TLSHandler {
	return &TLSHandler{tlsService: tlsSvc}
}

type InstallTLSRequest struct {
	CertPEM string `json:"cert_pem"`
	KeyPEM  string `json:"key_pem"`
}

func (h *TLSHandler) Get(w http.ResponseWriter, r *http.Request) {
	domName := chi.URLParam(r, "domain")
	report, err := h.tlsService.Validate(r.Context(), domName)
	if err != nil {
		response.Error(w, r, http.StatusNotFound, response.ErrCodeNotFound, "tls certificate not found", err.Error())
		return
	}

	response.JSON(w, http.StatusOK, report)
}

func (h *TLSHandler) Install(w http.ResponseWriter, r *http.Request) {
	domName := chi.URLParam(r, "domain")
	var req InstallTLSRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.ErrCodeValidationError, "malformed request payload", err.Error())
		return
	}

	if req.CertPEM == "" || req.KeyPEM == "" {
		response.Error(w, r, http.StatusBadRequest, response.ErrCodeValidationError, "cert_pem and key_pem are required", nil)
		return
	}

	report, err := h.tlsService.Provider().Install(r.Context(), domName, []byte(req.CertPEM), []byte(req.KeyPEM))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.ErrCodeValidationError, "failed to install tls certificate", err.Error())
		return
	}

	response.JSON(w, http.StatusOK, report)
}
