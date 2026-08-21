package handler

import (
	"encoding/json"
	"net/http"

	"github.com/azdharsyahputra/openmail/internal/api/response"
	"github.com/azdharsyahputra/openmail/internal/dkim"
	"github.com/go-chi/chi/v5"
)

type DKIMHandler struct {
	dkimService dkim.Service
}

func NewDKIMHandler(dkimSvc dkim.Service) *DKIMHandler {
	return &DKIMHandler{dkimService: dkimSvc}
}

type GenerateDKIMRequest struct {
	Selector string `json:"selector"`
}

func (h *DKIMHandler) List(w http.ResponseWriter, r *http.Request) {
	domName := chi.URLParam(r, "domain")
	keys, err := h.dkimService.ListKeys(r.Context(), domName)
	if err != nil {
		response.Error(w, r, http.StatusInternalServerError, response.ErrCodeInternal, "failed to list dkim keys", err.Error())
		return
	}

	response.JSON(w, http.StatusOK, keys)
}

func (h *DKIMHandler) Generate(w http.ResponseWriter, r *http.Request) {
	domName := chi.URLParam(r, "domain")
	var req GenerateDKIMRequest
	_ = json.NewDecoder(r.Body).Decode(&req)

	if req.Selector == "" {
		req.Selector = "default"
	}

	keyRecord, _, err := h.dkimService.GenerateKey(r.Context(), domName, req.Selector)
	if err != nil {
		response.Error(w, r, http.StatusInternalServerError, response.ErrCodeInternal, "failed to generate dkim key", err.Error())
		return
	}

	dnsRec, _ := h.dkimService.GetDNSRecord(r.Context(), domName, req.Selector)

	response.JSON(w, http.StatusCreated, map[string]interface{}{
		"key":        keyRecord,
		"dns_record": dnsRec,
	})
}

func (h *DKIMHandler) Verify(w http.ResponseWriter, r *http.Request) {
	domName := chi.URLParam(r, "domain")
	selector := chi.URLParam(r, "selector")

	res, err := h.dkimService.VerifyDNS(r.Context(), domName, selector, nil)
	if err != nil {
		response.Error(w, r, http.StatusInternalServerError, response.ErrCodeInternal, "failed to verify dkim dns", err.Error())
		return
	}

	response.JSON(w, http.StatusOK, res)
}

func (h *DKIMHandler) Activate(w http.ResponseWriter, r *http.Request) {
	domName := chi.URLParam(r, "domain")
	selector := chi.URLParam(r, "selector")

	if err := h.dkimService.ActivateKey(r.Context(), domName, selector); err != nil {
		response.Error(w, r, http.StatusInternalServerError, response.ErrCodeInternal, "failed to activate dkim key", err.Error())
		return
	}

	response.JSON(w, http.StatusOK, map[string]string{"message": "dkim selector activated successfully"})
}

func (h *DKIMHandler) Revoke(w http.ResponseWriter, r *http.Request) {
	domName := chi.URLParam(r, "domain")
	selector := chi.URLParam(r, "selector")

	if err := h.dkimService.RevokeKey(r.Context(), domName, selector); err != nil {
		response.Error(w, r, http.StatusInternalServerError, response.ErrCodeInternal, "failed to revoke dkim key", err.Error())
		return
	}

	response.JSON(w, http.StatusOK, map[string]string{"message": "dkim selector revoked successfully"})
}
