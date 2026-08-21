package middleware

import (
	"encoding/json"
	"net/http"
	"strings"
)

const DefaultMaxBodyBytes = 1 << 20 // 1MB

func BodyLimit(maxBytes int64) func(http.Handler) http.Handler {
	if maxBytes <= 0 {
		maxBytes = DefaultMaxBodyBytes
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch {
				// Validate Content-Type if body is expected
				ct := r.Header.Get("Content-Type")
				if r.ContentLength > 0 && ct != "" && !strings.HasPrefix(strings.ToLower(ct), "application/json") {
					respondUnsupportedMediaType(w, r, "Content-Type must be application/json")
					return
				}

				r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
			}
			next.ServeHTTP(w, r)
		})
	}
}

func respondUnsupportedMediaType(w http.ResponseWriter, r *http.Request, message string) {
	reqID, _ := r.Context().Value(RequestIDKey).(string)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusUnsupportedMediaType)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"error": map[string]string{
			"code":       "VALIDATION_ERROR",
			"message":    message,
			"request_id": reqID,
		},
	})
}
