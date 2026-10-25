package server

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/bravo68web/atrium/internal/app"
	"github.com/bravo68web/atrium/internal/background"
	"github.com/bravo68web/atrium/internal/config"
	"github.com/bravo68web/atrium/internal/database"
	"github.com/bravo68web/atrium/internal/log"
	"github.com/bravo68web/atrium/internal/queue"
)

type Server struct {
	cfg    *config.Config
	router *chi.Mux
	server *http.Server
	close  func()
}

func New(cfg *config.Config, db *database.DB, q queue.Queue) (*Server, error) {
	built, err := app.Build(cfg, db, q, nil)
	if err != nil {
		return nil, err
	}
	s := &Server{cfg: cfg, router: built.Mux, close: built.Close}
	s.server = &http.Server{
		Addr:         fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port),
		Handler:      s.router,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	return s, nil
}

func (s *Server) GetRouter() *chi.Mux {
	return s.router
}

func (s *Server) Start() error {
	return s.server.ListenAndServe()
}

func (s *Server) Stop() error {
	if s.close != nil {
		s.close()
	}
	return s.server.Close()
}

func (s *Server) StartWithGracefulShutdown() {
	go func() {
		log.Info("starting OAuth server", "host", s.cfg.Server.Host, "port", s.cfg.Server.Port)
		if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal("server failed", "err", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Info("shutting down server")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := s.server.Shutdown(ctx); err != nil {
		log.Fatal("server forced to shutdown", "err", err)
	}
	background.Wait()
	if s.close != nil {
		s.close()
	}

	log.Info("server exited")
}
