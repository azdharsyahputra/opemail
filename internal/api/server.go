package api

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

type Server struct {
	httpServer *http.Server
}

func NewServer(addr string, handler http.Handler) *Server {
	if addr == "" {
		addr = ":8080"
	}
	return &Server{
		httpServer: &http.Server{
			Addr:              addr,
			Handler:           handler,
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       15 * time.Second,
			WriteTimeout:      30 * time.Second,
			IdleTimeout:       60 * time.Second,
		},
	}
}

func (s *Server) Start() error {
	if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("http server failed: %w", err)
	}
	return nil
}

func (s *Server) Shutdown(ctx context.Context) error {
	return s.httpServer.Shutdown(ctx)
}
