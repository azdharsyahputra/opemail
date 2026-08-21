package handler

import (
	"net/http"

	"github.com/azdharsyahputra/openmail/internal/metrics"
)

type MetricsHandler struct {
	registry *metrics.Registry
}

func NewMetricsHandler(registry *metrics.Registry) *MetricsHandler {
	if registry == nil {
		registry = metrics.DefaultRegistry
	}
	return &MetricsHandler{registry: registry}
}

func (h *MetricsHandler) Metrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(h.registry.RenderPrometheus()))
}
