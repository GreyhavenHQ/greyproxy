package greyproxy

import (
	"embed"
	"net"
	"net/http"
	"os"
	"path/filepath"

	"github.com/greyhavenhq/greyproxy/internal/gostcore/logger"
	"github.com/greyhavenhq/greyproxy/internal/gostcore/service"
)

//go:embed static/*
var StaticFS embed.FS

// Service implements service.Service for the proxy API.
type Service struct {
	server  *http.Server
	addr    net.Addr
	DB      *DB
	Cache   *DNSCache
	Bus     *EventBus
	Waiters *WaiterTracker
}

func (s *Service) Serve() error {
	return s.server.ListenAndServe()
}

func (s *Service) Addr() net.Addr {
	return s.addr
}

func (s *Service) Close() error {
	if s.DB != nil {
		s.DB.Close()
	}
	return s.server.Close()
}

// SetHandler sets the HTTP handler for the service.
func (s *Service) SetHandler(h http.Handler) {
	s.server.Handler = h
}

// Ensure Service implements service.Service
var _ service.Service = (*Service)(nil)

// NewService creates a new proxy API service but does NOT start it.
// The caller should register plugins and then call Serve().
func NewService(cfg *Config, handler http.Handler) (*Service, error) {
	if cfg.Addr == "" {
		cfg.Addr = ":43080"
	}

	addr, err := net.ResolveTCPAddr("tcp", cfg.Addr)
	if err != nil {
		return nil, err
	}

	if dir := filepath.Dir(cfg.DB); dir != "." {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return nil, err
		}
	}

	db, err := OpenDB(cfg.DB)
	if err != nil {
		return nil, err
	}

	if err := db.Migrate(); err != nil {
		db.Close()
		return nil, err
	}

	log := logger.Default().WithFields(map[string]any{"kind": "service", "service": "@greyproxy"})
	log.Infof("database opened: %s", cfg.DB)

	bus := NewEventBus()
	return &Service{
		server: &http.Server{
			Addr:    cfg.Addr,
			Handler: handler,
		},
		addr:    addr,
		DB:      db,
		Cache:   NewDNSCache(),
		Bus:     bus,
		Waiters: NewWaiterTracker(bus),
	}, nil
}
