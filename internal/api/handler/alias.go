package handler

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/azdharsyahputra/openmail/internal/api/response"
	"github.com/azdharsyahputra/openmail/internal/domain"
	"github.com/azdharsyahputra/openmail/internal/mailbox"
	"github.com/go-chi/chi/v5"
)

type AliasHandler struct {
	aliasRepo   mailbox.AliasRepository
	mailboxRepo mailbox.Repository
	domainRepo  domain.Repository
}

func NewAliasHandler(aliasRepo mailbox.AliasRepository, mbRepo mailbox.Repository, domRepo domain.Repository) *AliasHandler {
	return &AliasHandler{
		aliasRepo:   aliasRepo,
		mailboxRepo: mbRepo,
		domainRepo:  domRepo,
	}
}

type CreateAliasRequest struct {
	Source string `json:"source"`
}

func (h *AliasHandler) List(w http.ResponseWriter, r *http.Request) {
	email := chi.URLParam(r, "email")
	aliases, err := h.aliasRepo.ListAliasesByDestination(r.Context(), email)
	if err != nil {
		response.Error(w, r, http.StatusInternalServerError, response.ErrCodeInternal, "failed to list aliases", err.Error())
		return
	}

	response.JSON(w, http.StatusOK, response.DataListResponse{
		Data: aliases,
		Pagination: response.PaginationResponse{
			Total: len(aliases),
			Limit: len(aliases),
		},
	})
}

func (h *AliasHandler) Create(w http.ResponseWriter, r *http.Request) {
	destEmail := chi.URLParam(r, "email")
	var req CreateAliasRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.ErrCodeValidationError, "malformed request payload", err.Error())
		return
	}

	req.Source = strings.TrimSpace(strings.ToLower(req.Source))
	if req.Source == "" {
		response.Error(w, r, http.StatusBadRequest, response.ErrCodeValidationError, "source alias is required", nil)
		return
	}

	// 1. Verify target mailbox exists
	mb, err := h.mailboxRepo.GetByEmail(r.Context(), destEmail)
	if err != nil {
		response.Error(w, r, http.StatusNotFound, response.ErrCodeMailboxNotFound, "destination mailbox does not exist", nil)
		return
	}

	// 2. Verify source domain exists and is active
	parts := strings.Split(req.Source, "@")
	if len(parts) != 2 {
		response.Error(w, r, http.StatusBadRequest, response.ErrCodeValidationError, "invalid source alias format", nil)
		return
	}
	sourceDom, err := h.domainRepo.GetByName(r.Context(), parts[1])
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.ErrCodeDomainNotFound, "source alias domain is not registered", nil)
		return
	}
	if sourceDom.Status != "active" {
		response.Error(w, r, http.StatusBadRequest, response.ErrCodeValidationError, "source alias domain is inactive", nil)
		return
	}

	aliasRecord := &mailbox.Alias{
		DomainID:    sourceDom.ID,
		Source:      req.Source,
		Destination: mb.Email,
	}

	if err := h.aliasRepo.CreateAlias(r.Context(), aliasRecord); err != nil {
		if err == mailbox.ErrAliasAlreadyExists {
			response.Error(w, r, http.StatusConflict, response.ErrCodeAliasExists, "alias already exists", nil)
			return
		}
		response.Error(w, r, http.StatusInternalServerError, response.ErrCodeInternal, "failed to create alias", err.Error())
		return
	}

	response.JSON(w, http.StatusCreated, aliasRecord)
}

func (h *AliasHandler) Delete(w http.ResponseWriter, r *http.Request) {
	destEmail := chi.URLParam(r, "email")
	sourceAlias := chi.URLParam(r, "alias")

	err := h.aliasRepo.DeleteAlias(r.Context(), sourceAlias, destEmail)
	if err != nil {
		if err == mailbox.ErrAliasNotFound {
			response.Error(w, r, http.StatusNotFound, response.ErrCodeAliasNotFound, "alias not found", nil)
			return
		}
		response.Error(w, r, http.StatusInternalServerError, response.ErrCodeInternal, "failed to delete alias", err.Error())
		return
	}

	response.JSON(w, http.StatusOK, map[string]string{"message": "alias deleted successfully"})
}
