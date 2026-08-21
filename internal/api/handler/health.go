package handler

import (
	"database/sql"
	"net/http"
	"strings"

	"github.com/azdharsyahputra/openmail/internal/api/response"
	"github.com/azdharsyahputra/openmail/internal/health"
	"github.com/azdharsyahputra/openmail/internal/queue"
	"github.com/azdharsyahputra/openmail/internal/system"
)

type HealthHandler struct {
	checker *health.Checker
	db      *sql.DB
	qSvc    queue.Service
	vmailDir string
	tlsPath  string
	dkimPath string
}

func NewHealthHandler(db *sql.DB, qSvc queue.Service, vmailDir, tlsPath, dkimPath string) *HealthHandler {
	return &HealthHandler{
		checker:  health.NewChecker(db, qSvc, vmailDir, tlsPath, dkimPath),
		db:       db,
		qSvc:     qSvc,
		vmailDir: vmailDir,
		tlsPath:  tlsPath,
		dkimPath: dkimPath,
	}
}

func (h *HealthHandler) Live(w http.ResponseWriter, r *http.Request) {
	status := h.checker.Live(r.Context())
	response.JSON(w, http.StatusOK, status)
}

func (h *HealthHandler) Ready(w http.ResponseWriter, r *http.Request) {
	status := h.checker.Ready(r.Context())
	statusCode := http.StatusOK
	if strings.ToUpper(status.Status) != "OK" {
		statusCode = http.StatusServiceUnavailable
	}
	response.JSON(w, statusCode, status)
}

func (h *HealthHandler) Deep(w http.ResponseWriter, r *http.Request) {
	status := h.checker.Deep(r.Context())
	statusCode := http.StatusOK
	if strings.ToUpper(status.Status) != "OK" {
		statusCode = http.StatusServiceUnavailable
	}
	response.JSON(w, statusCode, status)
}

func (h *HealthHandler) SystemDoctor(w http.ResponseWriter, r *http.Request) {
	deps := system.SystemDoctorDeps{
		DB:           h.db,
		QueueService: h.qSvc,
		VmailDir:     h.vmailDir,
		TLSPath:      h.tlsPath,
		DKIMPath:     h.dkimPath,
	}
	report := system.RunSystemDoctor(r.Context(), deps)
	response.JSON(w, http.StatusOK, report)
}
