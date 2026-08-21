package middleware

import (
	"log/slog"
	"net/http"
	"time"
)

type responseWriterWrapper struct {
	http.ResponseWriter
	statusCode int
	bytesWritten int64
}

func (rw *responseWriterWrapper) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseWriterWrapper) Write(b []byte) (int, error) {
	n, err := rw.ResponseWriter.Write(b)
	rw.bytesWritten += int64(n)
	return n, err
}

func Logging(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			wrapper := &responseWriterWrapper{ResponseWriter: w, statusCode: http.StatusOK}
			reqID, _ := r.Context().Value(RequestIDKey).(string)

			next.ServeHTTP(wrapper, r)

			duration := time.Since(start)
			if logger != nil {
				logger.Info("http_request",
					slog.String("request_id", reqID),
					slog.String("method", r.Method),
					slog.String("path", r.URL.Path),
					slog.Int("status", wrapper.statusCode),
					slog.Duration("latency", duration),
					slog.String("remote_addr", r.RemoteAddr),
				)
			}
		})
	}
}
