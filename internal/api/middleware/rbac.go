package middleware

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
)

func RequireRole(allowedRoles ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := GetClaims(r.Context())
			if claims == nil {
				respondForbidden(w, r, "access denied: authentication required")
				return
			}

			userRole := strings.ToLower(claims.Role)
			// Admin role always has wildcard access
			if userRole == "admin" {
				next.ServeHTTP(w, r)
				return
			}

			permitted := false
			for _, role := range allowedRoles {
				if strings.EqualFold(userRole, role) {
					permitted = true
					break
				}
			}

			if !permitted {
				respondForbidden(w, r, "access denied: insufficient role permissions")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func RequireMailboxOwnership() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := GetClaims(r.Context())
			if claims == nil {
				respondForbidden(w, r, "access denied: authentication required")
				return
			}

			userRole := strings.ToLower(claims.Role)
			// Admin, Operator, Auditor bypass mailbox ownership check
			if userRole == "admin" || userRole == "operator" || userRole == "auditor" {
				next.ServeHTTP(w, r)
				return
			}

			targetEmail := chi.URLParam(r, "email")
			if targetEmail != "" && !strings.EqualFold(claims.Email, targetEmail) {
				respondForbidden(w, r, "access denied: cross-user resource access forbidden")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func respondForbidden(w http.ResponseWriter, r *http.Request, message string) {
	reqID, _ := r.Context().Value(RequestIDKey).(string)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"error": map[string]string{
			"code":       "FORBIDDEN",
			"message":    message,
			"request_id": reqID,
		},
	})
}
