package handler

import (
	"encoding/json"
	"net/http"

	"github.com/azdharsyahputra/openmail/internal/api/response"
	"github.com/azdharsyahputra/openmail/internal/identity"
)

type IdentityHandler struct {
	identService identity.Service
}

func NewIdentityHandler(identSvc identity.Service) *IdentityHandler {
	return &IdentityHandler{identService: identSvc}
}

type SyncRequest struct {
	DomainName        string `json:"domain_name"`
	AutoCreateMailbox bool   `json:"auto_create_mailbox"`
	DryRun            bool   `json:"dry_run"`
}

func (h *IdentityHandler) ListProviders(w http.ResponseWriter, r *http.Request) {
	providers := []map[string]interface{}{
		{
			"name":        "local",
			"type":        "postgresql",
			"description": "Built-in PostgreSQL local password identity store",
		},
		{
			"name":        "ldap",
			"type":        "openldap/active_directory",
			"description": "External LDAP / Active Directory enterprise directory provider",
		},
	}
	response.JSON(w, http.StatusOK, providers)
}

func (h *IdentityHandler) LDAPDoctor(w http.ResponseWriter, r *http.Request) {
	report, err := h.identService.Doctor(r.Context())
	if err != nil {
		response.Error(w, r, http.StatusInternalServerError, response.ErrCodeInternal, "failed to run ldap doctor", err.Error())
		return
	}

	response.JSON(w, http.StatusOK, report)
}

func (h *IdentityHandler) LDAPSync(w http.ResponseWriter, r *http.Request) {
	var req SyncRequest
	_ = json.NewDecoder(r.Body).Decode(&req)

	report, err := h.identService.Sync(r.Context(), identity.SyncOptions{
		DomainName:        req.DomainName,
		AutoCreateMailbox: req.AutoCreateMailbox,
		DryRun:            req.DryRun,
	})
	if err != nil {
		response.Error(w, r, http.StatusInternalServerError, response.ErrCodeLDAPSyncFailed, "failed to synchronize ldap directory", err.Error())
		return
	}

	response.JSON(w, http.StatusOK, report)
}
