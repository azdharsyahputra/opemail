package logger

import (
	"context"
	"io"
	"log/slog"
	"os"
	"strings"
)

var sensitiveKeys = map[string]bool{
	"password":      true,
	"pass":          true,
	"secret":        true,
	"private_key":   true,
	"privkey":       true,
	"auth_plain":    true,
	"credentials":   true,
	"token":         true,
	"body":          true,
	"email_content": true,
}

type SecretMaskHandler struct {
	inner slog.Handler
}

func NewSecretMaskHandler(w io.Writer, level slog.Level) *SecretMaskHandler {
	opts := &slog.HandlerOptions{
		Level: level,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			keyLower := strings.ToLower(a.Key)
			if sensitiveKeys[keyLower] {
				return slog.String(a.Key, "[REDACTED]")
			}
			return a
		},
	}
	return &SecretMaskHandler{
		inner: slog.NewJSONHandler(w, opts),
	}
}

func (h *SecretMaskHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.inner.Enabled(ctx, level)
}

func (h *SecretMaskHandler) Handle(ctx context.Context, r slog.Record) error {
	return h.inner.Handle(ctx, r)
}

func (h *SecretMaskHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	var clean []slog.Attr
	for _, a := range attrs {
		if sensitiveKeys[strings.ToLower(a.Key)] {
			clean = append(clean, slog.String(a.Key, "[REDACTED]"))
		} else {
			clean = append(clean, a)
		}
	}
	return &SecretMaskHandler{inner: h.inner.WithAttrs(clean)}
}

func (h *SecretMaskHandler) WithGroup(name string) slog.Handler {
	return &SecretMaskHandler{inner: h.inner.WithGroup(name)}
}

// InitDefaultLogger configures the global slog logger with JSON output and secret masking.
func InitDefaultLogger(level slog.Level) *slog.Logger {
	handler := NewSecretMaskHandler(os.Stdout, level)
	logger := slog.New(handler)
	slog.SetDefault(logger)
	return logger
}
