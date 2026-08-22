package handler

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"

	"github.com/azdharsyahputra/openmail/internal/api/middleware"
	"github.com/azdharsyahputra/openmail/internal/api/response"
	"github.com/azdharsyahputra/openmail/internal/webmail"
	"github.com/go-chi/chi/v5"
)

func cleanMsgID(raw string) string {
	if unescaped, err := url.PathUnescape(raw); err == nil {
		raw = unescaped
	}
	if unescaped, err := url.QueryUnescape(raw); err == nil {
		raw = unescaped
	}
	return raw
}

type WebmailHandler struct {
	webmailService webmail.Service
}

func NewWebmailHandler(webmailService webmail.Service) *WebmailHandler {
	return &WebmailHandler{
		webmailService: webmailService,
	}
}

func (h *WebmailHandler) ListFolders(w http.ResponseWriter, r *http.Request) {
	email := middleware.GetEmail(r.Context())
	if email == "" {
		response.Error(w, r, http.StatusUnauthorized, response.ErrCodeUnauthorized, "unauthorized", nil)
		return
	}

	folders, err := h.webmailService.ListFolders(r.Context(), email)
	if err != nil {
		response.Error(w, r, http.StatusInternalServerError, response.ErrCodeInternal, "failed to list folders", err.Error())
		return
	}

	response.JSON(w, http.StatusOK, map[string]interface{}{
		"email":   email,
		"folders": folders,
	})
}

func (h *WebmailHandler) ListMessages(w http.ResponseWriter, r *http.Request) {
	email := middleware.GetEmail(r.Context())
	if email == "" {
		response.Error(w, r, http.StatusUnauthorized, response.ErrCodeUnauthorized, "unauthorized", nil)
		return
	}

	folder := r.URL.Query().Get("folder")
	if folder == "" {
		folder = "inbox"
	}

	page := 1
	if p, err := strconv.Atoi(r.URL.Query().Get("page")); err == nil && p > 0 {
		page = p
	}

	limit := 25
	if l, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && l > 0 {
		limit = l
	}

	search := r.URL.Query().Get("q")

	messages, total, err := h.webmailService.ListMessages(r.Context(), email, folder, page, limit, search)
	if err != nil {
		response.Error(w, r, http.StatusInternalServerError, response.ErrCodeInternal, "failed to list messages", err.Error())
		return
	}

	response.JSON(w, http.StatusOK, map[string]interface{}{
		"folder":   folder,
		"page":     page,
		"limit":    limit,
		"total":    total,
		"messages": messages,
	})
}

func (h *WebmailHandler) GetMessage(w http.ResponseWriter, r *http.Request) {
	email := middleware.GetEmail(r.Context())
	if email == "" {
		response.Error(w, r, http.StatusUnauthorized, response.ErrCodeUnauthorized, "unauthorized", nil)
		return
	}

	msgID := cleanMsgID(chi.URLParam(r, "id"))
	folder := r.URL.Query().Get("folder")
	if folder == "" {
		folder = "inbox"
	}

	detail, err := h.webmailService.GetMessage(r.Context(), email, folder, msgID)
	if err != nil {
		response.Error(w, r, http.StatusNotFound, response.ErrCodeInternal, "message not found", err.Error())
		return
	}

	response.JSON(w, http.StatusOK, detail)
}

func (h *WebmailHandler) SendMessage(w http.ResponseWriter, r *http.Request) {
	email := middleware.GetEmail(r.Context())
	if email == "" {
		response.Error(w, r, http.StatusUnauthorized, response.ErrCodeUnauthorized, "unauthorized", nil)
		return
	}

	var req webmail.SendMessageRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.ErrCodeValidationError, "malformed request payload", err.Error())
		return
	}

	if len(req.To) == 0 {
		response.Error(w, r, http.StatusBadRequest, response.ErrCodeValidationError, "at least one recipient is required", nil)
		return
	}

	res, err := h.webmailService.SendMessage(r.Context(), email, req)
	if err != nil {
		response.Error(w, r, http.StatusInternalServerError, response.ErrCodeInternal, "failed to deliver message", err.Error())
		return
	}

	response.JSON(w, http.StatusOK, res)
}

type MarkReadRequest struct {
	Read bool `json:"read"`
}

func (h *WebmailHandler) MarkRead(w http.ResponseWriter, r *http.Request) {
	email := middleware.GetEmail(r.Context())
	if email == "" {
		response.Error(w, r, http.StatusUnauthorized, response.ErrCodeUnauthorized, "unauthorized", nil)
		return
	}

	msgID := cleanMsgID(chi.URLParam(r, "id"))
	folder := r.URL.Query().Get("folder")
	if folder == "" {
		folder = "inbox"
	}

	var req MarkReadRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		req.Read = true
	}

	if err := h.webmailService.MarkMessageRead(r.Context(), email, folder, msgID, req.Read); err != nil {
		response.Error(w, r, http.StatusInternalServerError, response.ErrCodeInternal, "failed to update read status", err.Error())
		return
	}

	response.JSON(w, http.StatusOK, map[string]bool{"success": true, "read": req.Read})
}

type MoveMessageRequest struct {
	SrcFolder string `json:"src_folder"`
	DstFolder string `json:"dst_folder"`
}

func (h *WebmailHandler) MoveMessage(w http.ResponseWriter, r *http.Request) {
	email := middleware.GetEmail(r.Context())
	if email == "" {
		response.Error(w, r, http.StatusUnauthorized, response.ErrCodeUnauthorized, "unauthorized", nil)
		return
	}

	msgID := cleanMsgID(chi.URLParam(r, "id"))
	var req MoveMessageRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.DstFolder == "" {
		response.Error(w, r, http.StatusBadRequest, response.ErrCodeValidationError, "src_folder and dst_folder are required", nil)
		return
	}

	if req.SrcFolder == "" {
		req.SrcFolder = "inbox"
	}

	if err := h.webmailService.MoveMessage(r.Context(), email, req.SrcFolder, req.DstFolder, msgID); err != nil {
		response.Error(w, r, http.StatusInternalServerError, response.ErrCodeInternal, "failed to move message", err.Error())
		return
	}

	response.JSON(w, http.StatusOK, map[string]bool{"success": true})
}

func (h *WebmailHandler) DeleteMessage(w http.ResponseWriter, r *http.Request) {
	email := middleware.GetEmail(r.Context())
	if email == "" {
		response.Error(w, r, http.StatusUnauthorized, response.ErrCodeUnauthorized, "unauthorized", nil)
		return
	}

	msgID := cleanMsgID(chi.URLParam(r, "id"))
	folder := r.URL.Query().Get("folder")
	if folder == "" {
		folder = "inbox"
	}

	if err := h.webmailService.DeleteMessage(r.Context(), email, folder, msgID); err != nil {
		response.Error(w, r, http.StatusInternalServerError, response.ErrCodeInternal, "failed to delete message", err.Error())
		return
	}

	response.JSON(w, http.StatusOK, map[string]bool{"success": true})
}

func (h *WebmailHandler) GetAttachment(w http.ResponseWriter, r *http.Request) {
	email := middleware.GetEmail(r.Context())
	if email == "" {
		response.Error(w, r, http.StatusUnauthorized, response.ErrCodeUnauthorized, "unauthorized", nil)
		return
	}

	msgID := cleanMsgID(chi.URLParam(r, "id"))
	attID := cleanMsgID(chi.URLParam(r, "attId"))
	folder := r.URL.Query().Get("folder")
	if folder == "" {
		folder = "inbox"
	}

	filename, cType, data, err := h.webmailService.GetAttachment(r.Context(), email, folder, msgID, attID)
	if err != nil {
		response.Error(w, r, http.StatusNotFound, response.ErrCodeInternal, "attachment not found", err.Error())
		return
	}

	if cType == "" {
		cType = "application/octet-stream"
	}

	w.Header().Set("Content-Type", cType)
	w.Header().Set("Content-Disposition", "attachment; filename=\""+filename+"\"")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}
