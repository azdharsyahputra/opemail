package logger_test

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/azdharsyahputra/openmail/internal/logger"
)

func TestSecretMaskHandler(t *testing.T) {
	var buf bytes.Buffer
	handler := logger.NewSecretMaskHandler(&buf, slog.LevelInfo)
	log := slog.New(handler)

	ctx := context.Background()
	log.InfoContext(ctx, "user authenticated",
		slog.String("component", "smtp"),
		slog.String("recipient", "ajar@example.com"),
		slog.String("password", "SuperSecret123!"),
		slog.String("auth_plain", "AHVzZXIAcGFzc3dvcmQ="),
		slog.String("private_key", "-----BEGIN PRIVATE KEY-----..."),
	)

	output := buf.String()
	if strings.Contains(output, "SuperSecret123!") {
		t.Errorf("password was leaked in log output: %s", output)
	}
	if strings.Contains(output, "AHVzZXIAcGFzc3dvcmQ=") {
		t.Errorf("auth_plain was leaked in log output: %s", output)
	}
	if strings.Contains(output, "-----BEGIN PRIVATE KEY-----") {
		t.Errorf("private_key was leaked in log output: %s", output)
	}
	if !strings.Contains(output, "[REDACTED]") {
		t.Errorf("expected [REDACTED] in log output: %s", output)
	}
}
