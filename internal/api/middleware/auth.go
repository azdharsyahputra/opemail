package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/azdharsyahputra/openmail/internal/api/token"
)

const ClaimsKey contextKey = "claims"

func Authenticate(tokenMgr token.Manager) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" || !strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
				respondUnauthorized(w, r, "missing or malformed authorization bearer header")
				return
			}

			rawToken := strings.TrimSpace(authHeader[7:])
			claims, err := tokenMgr.ValidateAccessToken(r.Context(), rawToken)
			if err != nil {
				respondUnauthorized(w, r, "invalid, expired, or revoked access token")
				return
			}

			ctx := context.WithValue(r.Context(), ClaimsKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func GetClaims(ctx context.Context) *token.Claims {
	if val := ctx.Value(ClaimsKey); val != nil {
		if c, ok := val.(*token.Claims); ok {
			return c
		}
	}
	return nil
}

func GetEmail(ctx context.Context) string {
	if c := GetClaims(ctx); c != nil {
		return c.Email
	}
	return ""
}

func respondUnauthorized(w http.ResponseWriter, r *http.Request, message string) {
	reqID, _ := r.Context().Value(RequestIDKey).(string)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"error": map[string]string{
			"code":       "AUTH_UNAUTHORIZED",
			"message":    message,
			"request_id": reqID,
		},
	})
}
