package handler

import (
	"net/http"

	"github.com/azdharsyahputra/openmail/internal/api/response"
	"github.com/azdharsyahputra/openmail/internal/queue"
	"github.com/go-chi/chi/v5"
)

type QueueHandler struct {
	queueService queue.Service
}

func NewQueueHandler(qSvc queue.Service) *QueueHandler {
	return &QueueHandler{queueService: qSvc}
}

func (h *QueueHandler) Status(w http.ResponseWriter, r *http.Request) {
	status, err := h.queueService.GetStatus(r.Context())
	if err != nil {
		response.Error(w, r, http.StatusInternalServerError, response.ErrCodeQueueOpFailed, "failed to get queue status", err.Error())
		return
	}

	response.JSON(w, http.StatusOK, status)
}

func (h *QueueHandler) List(w http.ResponseWriter, r *http.Request) {
	filter := r.URL.Query().Get("status")
	messages, err := h.queueService.List(r.Context(), filter)
	if err != nil {
		response.Error(w, r, http.StatusInternalServerError, response.ErrCodeQueueOpFailed, "failed to list queue messages", err.Error())
		return
	}

	response.JSON(w, http.StatusOK, response.DataListResponse{
		Data: messages,
		Pagination: response.PaginationResponse{
			Total: len(messages),
			Limit: len(messages),
		},
	})
}

func (h *QueueHandler) Inspect(w http.ResponseWriter, r *http.Request) {
	queueID := chi.URLParam(r, "id")
	content, err := h.queueService.Inspect(r.Context(), queueID)
	if err != nil {
		response.Error(w, r, http.StatusNotFound, response.ErrCodeQueueMessageNotFound, "queue message not found", err.Error())
		return
	}

	response.JSON(w, http.StatusOK, map[string]string{
		"queue_id": queueID,
		"content":  content,
	})
}

func (h *QueueHandler) Retry(w http.ResponseWriter, r *http.Request) {
	queueID := chi.URLParam(r, "id")
	if err := h.queueService.Retry(r.Context(), queueID); err != nil {
		response.Error(w, r, http.StatusInternalServerError, response.ErrCodeQueueOpFailed, "failed to retry message", err.Error())
		return
	}

	response.JSON(w, http.StatusOK, map[string]string{"message": "delivery retry scheduled for " + queueID})
}

func (h *QueueHandler) Hold(w http.ResponseWriter, r *http.Request) {
	queueID := chi.URLParam(r, "id")
	if err := h.queueService.Hold(r.Context(), queueID); err != nil {
		response.Error(w, r, http.StatusInternalServerError, response.ErrCodeQueueOpFailed, "failed to hold message", err.Error())
		return
	}

	response.JSON(w, http.StatusOK, map[string]string{"message": "message placed on hold: " + queueID})
}

func (h *QueueHandler) Release(w http.ResponseWriter, r *http.Request) {
	queueID := chi.URLParam(r, "id")
	if err := h.queueService.Release(r.Context(), queueID); err != nil {
		response.Error(w, r, http.StatusInternalServerError, response.ErrCodeQueueOpFailed, "failed to release message", err.Error())
		return
	}

	response.JSON(w, http.StatusOK, map[string]string{"message": "message released from hold: " + queueID})
}

func (h *QueueHandler) Delete(w http.ResponseWriter, r *http.Request) {
	queueID := chi.URLParam(r, "id")
	if err := h.queueService.Delete(r.Context(), queueID); err != nil {
		response.Error(w, r, http.StatusInternalServerError, response.ErrCodeQueueOpFailed, "failed to delete message", err.Error())
		return
	}

	response.JSON(w, http.StatusOK, map[string]string{"message": "message deleted from queue: " + queueID})
}

func (h *QueueHandler) Flush(w http.ResponseWriter, r *http.Request) {
	if err := h.queueService.Flush(r.Context()); err != nil {
		response.Error(w, r, http.StatusInternalServerError, response.ErrCodeQueueOpFailed, "failed to flush queue", err.Error())
		return
	}

	response.JSON(w, http.StatusOK, map[string]string{"message": "mail queue flushed successfully"})
}
