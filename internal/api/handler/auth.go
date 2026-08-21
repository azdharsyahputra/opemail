package handler

import (
	"encoding/json"
	"net/http"

	"github.com/azdharsyahputra/openmail/internal/api/middleware"
	"github.com/azdharsyahputra/openmail/internal/api/response"
	"github.com/azdharsyahputra/openmail/internal/api/token"
	"github.com/azdharsyahputra/openmail/internal/identity"
)


type AuthHandler struct {
	identService identity.Service
	tokenMgr     token.Manager
}

func NewAuthHandler(identService identity.Service, tokenMgr token.Manager) *AuthHandler {
	return &AuthHandler{
		identService: identService,
		tokenMgr:     tokenMgr,
	}
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type RefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.ErrCodeValidationError, "malformed request payload", err.Error())
		return
	}

	if req.Username == "" || req.Password == "" {
		response.Error(w, r, http.StatusBadRequest, response.ErrCodeValidationError, "username and password are required", nil)
		return
	}

	// Authenticate against identity service (multi-provider + gatekeeper)
	ident, err := h.identService.Authenticate(r.Context(), req.Username, req.Password)
	if err != nil {
		if err == identity.ErrAccountSuspended {
			response.Error(w, r, http.StatusForbidden, response.ErrCodeAccountSuspended, "account is suspended", nil)
			return
		}
		if err == identity.ErrAccountDisabled {
			response.Error(w, r, http.StatusForbidden, response.ErrCodeAccountDisabled, "account is disabled", nil)
			return
		}
		response.Error(w, r, http.StatusUnauthorized, response.ErrCodeInvalidCredentials, "invalid username or password", nil)
		return
	}

	primaryRole := "user"
	if len(ident.Roles) > 0 {
		primaryRole = string(ident.Roles[0])
	}

	tokenPair, err := h.tokenMgr.IssueTokenPair(r.Context(), nil, ident.Email, primaryRole)
	if err != nil {
		response.Error(w, r, http.StatusInternalServerError, response.ErrCodeInternal, "failed to issue authentication token", err.Error())
		return
	}

	response.JSON(w, http.StatusOK, map[string]interface{}{
		"access_token":  tokenPair.AccessToken,
		"refresh_token": tokenPair.RefreshToken,
		"token_type":    tokenPair.TokenType,
		"expires_in":    tokenPair.ExpiresIn,
		"user": map[string]interface{}{
			"id":           ident.ID,
			"username":     ident.Username,
			"email":        ident.Email,
			"display_name": ident.DisplayName,
			"roles":        ident.Roles,
			"provider":     ident.Provider,
		},
	})
}

func (h *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	var req RefreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.ErrCodeValidationError, "malformed request payload", err.Error())
		return
	}

	if req.RefreshToken == "" {
		response.Error(w, r, http.StatusBadRequest, response.ErrCodeValidationError, "refresh_token is required", nil)
		return
	}

	tokenPair, err := h.tokenMgr.RefreshTokens(r.Context(), req.RefreshToken)
	if err != nil {
		response.Error(w, r, http.StatusUnauthorized, response.ErrCodeUnauthorized, "invalid or expired refresh token", nil)
		return
	}

	response.JSON(w, http.StatusOK, tokenPair)
}

func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	var req RefreshRequest
	_ = json.NewDecoder(r.Body).Decode(&req)

	if req.RefreshToken != "" {
		_ = h.tokenMgr.RevokeToken(r.Context(), req.RefreshToken)
	}

	claims := middleware.GetClaims(r.Context())
	if claims != nil {
		_ = h.tokenMgr.RevokeAllForEmail(r.Context(), claims.Email)
	}

	response.JSON(w, http.StatusOK, map[string]string{"message": "successfully logged out"})
}

func (h *AuthHandler) Me(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r.Context())
	if claims == nil {
		response.Error(w, r, http.StatusUnauthorized, response.ErrCodeUnauthorized, "unauthorized", nil)
		return
	}

	ident, err := h.identService.Lookup(r.Context(), claims.Email)
	if err != nil {
		response.JSON(w, http.StatusOK, map[string]interface{}{
			"email": claims.Email,
			"role":  claims.Role,
		})
		return
	}

	response.JSON(w, http.StatusOK, ident)
}

