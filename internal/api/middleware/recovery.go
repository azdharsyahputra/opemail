package middleware

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"runtime/debug"
)

func Recovery(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rec := recover(); rec != nil {
					reqID, _ := r.Context().Value(RequestIDKey).(string)
					stack := string(debug.Stack())
					if logger != nil {
						logger.Error("panic_recovered",
							slog.String("request_id", reqID),
							slog.Any("panic", rec),
							slog.String("stack", stack),
						)
					}

					w.Header().Set("Content-Type", "application/json; charset=utf-8")
					w.WriteHeader(http.StatusInternalServerError)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"error": map[string]string{
							"code":       "INTERNAL_ERROR",
							"message":    fmt.Sprintf("Internal server error: %v", rec),
							"request_id": reqID,
						},
					})
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}
