package handler

import (
	"encoding/json"
	"net/http"

	"github.com/azdharsyahputra/openmail/internal/api/response"
	"github.com/azdharsyahputra/openmail/internal/audit"
	"github.com/azdharsyahputra/openmail/internal/system"
)

type ConfigHandler struct {
	settingRepo  system.SettingRepository
	auditService audit.Service
}

func NewConfigHandler(settingRepo system.SettingRepository, auditService audit.Service) *ConfigHandler {
	return &ConfigHandler{
		settingRepo:  settingRepo,
		auditService: auditService,
	}
}

type UpdateConfigRequest struct {
	Settings map[string]string `json:"settings"`
}

func (h *ConfigHandler) Get(w http.ResponseWriter, r *http.Request) {
	settings, err := h.settingRepo.GetAll(r.Context())
	if err != nil {
		response.Error(w, r, http.StatusInternalServerError, response.ErrCodeInternal, "failed to get system settings", err.Error())
		return
	}

	response.JSON(w, http.StatusOK, map[string]interface{}{
		"settings": settings,
	})
}

func (h *ConfigHandler) Update(w http.ResponseWriter, r *http.Request) {
	var req UpdateConfigRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.ErrCodeValidationError, "malformed request body", err.Error())
		return
	}

	if len(req.Settings) == 0 {
		response.Error(w, r, http.StatusBadRequest, response.ErrCodeValidationError, "settings payload cannot be empty", nil)
		return
	}

	if err := h.settingRepo.SetBatch(r.Context(), req.Settings); err != nil {
		response.Error(w, r, http.StatusInternalServerError, response.ErrCodeInternal, "failed to update settings", err.Error())
		return
	}

	if h.auditService != nil {
		_ = h.auditService.RecordAudit(r.Context(), "api", nil, "config.update", "system_settings", nil, req.Settings)
	}

	updated, err := h.settingRepo.GetAll(r.Context())
	if err != nil {
		response.JSON(w, http.StatusOK, map[string]string{"status": "updated"})
		return
	}

	response.JSON(w, http.StatusOK, map[string]interface{}{
		"status":   "updated",
		"settings": updated,
	})
}
