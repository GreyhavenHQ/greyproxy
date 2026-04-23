package main

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/fsnotify/fsnotify"
	defaults "github.com/greyhavenhq/greyproxy"
	"github.com/greyhavenhq/greyproxy/internal/gostcore/logger"
	svccore "github.com/greyhavenhq/greyproxy/internal/gostcore/service"
	"github.com/greyhavenhq/greyproxy/internal/gostx"
	"github.com/greyhavenhq/greyproxy/internal/gostx/config"
	"github.com/greyhavenhq/greyproxy/internal/gostx/config/loader"
	auth_parser "github.com/greyhavenhq/greyproxy/internal/gostx/config/parsing/auth"
	"github.com/greyhavenhq/greyproxy/internal/gostx/config/parsing/parser"
	xmetrics "github.com/greyhavenhq/greyproxy/internal/gostx/metrics"
	metrics "github.com/greyhavenhq/greyproxy/internal/gostx/metrics/service"
	"github.com/greyhavenhq/greyproxy/internal/gostx/registry"
	greyproxy "github.com/greyhavenhq/greyproxy/internal/greyproxy"
	greyproxy_api "github.com/greyhavenhq/greyproxy/internal/greyproxy/api"
	"github.com/greyhavenhq/greyproxy/internal/greyproxy/middleware"
	greyproxy_plugins "github.com/greyhavenhq/greyproxy/internal/greyproxy/plugins"
	greyproxy_ui "github.com/greyhavenhq/greyproxy/internal/greyproxy/ui"
	"github.com/kardianos/service"
	"github.com/klauspost/compress/zstd"
	"github.com/spf13/viper"
)

type program struct {
	srvMetrics   svccore.Service
	srvGreyproxy *greyproxy.Service
	srvProfiling *http.Server

	cancel          context.CancelFunc
	assemblerCancel context.CancelFunc
	credStoreCancel context.CancelFunc
	mwCancel        context.CancelFunc

	certMtimeMu sync.Mutex
	certMtime   time.Time // mtime of ca-cert.pem at last successful reload
}

func (p *program) initParser() {
	parser.Init(parser.Args{
		CfgFile:       cfgFile,
		DefaultConfig: defaults.DefaultConfig,
		Services:      services,
		Nodes:         nodes,
		Debug:         debug,
		Trace:         trace,
		MetricsAddr:   metricsAddr,
	})
}

func (p *program) Start(s service.Service) error {
	cfg, err := parser.Parse()
	if err != nil {
		return err
	}

	if outputFormat != "" {
		if err := cfg.Write(os.Stdout, outputFormat); err != nil {
			return err
		}
		os.Exit(0)
	}

	// Auto-inject MITM cert paths if CA files exist
	injectCertPaths(cfg, greyproxyDataHome())

	// Replace hardcoded DNS upstream with the host's actual resolver
	injectSystemDNS(cfg)

	config.Set(cfg)

	// Override DNS handler to capture responses for DNS cache population.
	// Must happen before loader.Load creates services.
	greyproxy_plugins.OverrideDNSHandler()

	if err := loader.Load(cfg); err != nil {
		return err
	}

	if err := p.run(cfg); err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(context.Background())
	p.cancel = cancel
	go p.reload(ctx)
	go p.watchCertFiles(ctx, greyproxyDataHome())

	return nil
}

// injectCertPaths injects the CA cert/key paths into HTTP and SOCKS5 handler configs if the files exist.
func injectCertPaths(cfg *config.Config, dataDir string) {
	certFile := filepath.Join(dataDir, "ca-cert.pem")
	keyFile := filepath.Join(dataDir, "ca-key.pem")
	if _, err := os.Stat(certFile); err != nil {
		return
	}
	if _, err := os.Stat(keyFile); err != nil {
		return
	}
	for _, svc := range cfg.Services {
		if svc.Handler == nil {
			continue
		}
		if svc.Handler.Type != "http" && svc.Handler.Type != "socks5" {
			continue
		}
		if svc.Handler.Metadata == nil {
			svc.Handler.Metadata = make(map[string]any)
		}
		if _, ok := svc.Handler.Metadata["mitm.certFile"]; !ok {
			svc.Handler.Metadata["mitm.certFile"] = certFile
			svc.Handler.Metadata["mitm.keyFile"] = keyFile
		}
	}
}

// injectSystemDNS populates the upstream forwarder for any DNS proxy service
// that has no forwarder configured. The upstream is detected from the host's
// system resolver (/etc/resolv.conf on Linux/macOS, registry on Windows),
// falling back to 1.1.1.1:53 if detection fails.
//
// Services that already have a forwarder configured are left completely alone,
// which is how users opt out or override the upstream.
func injectSystemDNS(cfg *config.Config) {
	upstream := systemDNSServers()[0]
	for _, svc := range cfg.Services {
		if svc.Handler == nil || svc.Handler.Type != "dns" {
			continue
		}
		if svc.Forwarder != nil && len(svc.Forwarder.Nodes) > 0 {
			// User has explicitly configured a forwarder; leave it alone.
			continue
		}
		svc.Forwarder = &config.ForwarderConfig{
			Nodes: []*config.ForwardNodeConfig{
				{Name: "dns-upstream", Addr: upstream},
			},
		}
	}
	logger.Default().Infof("dns forwarder: upstream = %s", upstream)
}

// watchCertFiles watches ca-cert.pem and ca-key.pem using inotify (fsnotify) and
// triggers a config reload when either file is written or created.
func (p *program) watchCertFiles(ctx context.Context, dataDir string) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		logger.Default().Errorf("cert watcher: failed to create watcher: %v", err)
		return
	}
	defer func() { _ = watcher.Close() }()

	if err := watcher.Add(dataDir); err != nil {
		logger.Default().Errorf("cert watcher: failed to watch %s: %v", dataDir, err)
		return
	}

	certFile := filepath.Join(dataDir, "ca-cert.pem")
	keyFile := filepath.Join(dataDir, "ca-key.pem")

	var debounce *time.Timer
	sawCert, sawKey := false, false
	for {
		select {
		case <-ctx.Done():
			if debounce != nil {
				debounce.Stop()
			}
			return
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			if !event.Has(fsnotify.Write) && !event.Has(fsnotify.Create) {
				continue
			}
			if event.Name == certFile {
				sawCert = true
			} else if event.Name == keyFile {
				sawKey = true
			} else {
				continue
			}

			if !sawCert || !sawKey {
				continue
			}
			sawCert, sawKey = false, false
			if debounce != nil {
				debounce.Stop()
			}
			debounce = time.AfterFunc(100*time.Millisecond, func() {
				logger.Default().Info("cert files changed, reloading MITM cert...")
				if err := p.reloadConfig(); err != nil {
					logger.Default().Errorf("cert reload failed: %v", err)
				} else {
					logger.Default().Info("MITM cert reloaded")
				}
			})
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			logger.Default().Errorf("cert watcher error: %v", err)
		}
	}
}

func (p *program) run(cfg *config.Config) error {
	for _, svc := range registry.ServiceRegistry().GetAll() {
		svc := svc
		go func() {
			_ = svc.Serve()
		}()
	}

	if p.srvMetrics != nil {
		_ = p.srvMetrics.Close()
		p.srvMetrics = nil
	}
	if cfg.Metrics != nil && cfg.Metrics.Addr != "" {
		s, err := buildMetricsService(cfg.Metrics)
		if err != nil {
			return err
		}

		p.srvMetrics = s

		xmetrics.Enable(true)

		go func() {
			defer func() { _ = s.Close() }()

			log := logger.Default().WithFields(map[string]any{"kind": "service", "service": "@metrics"})

			log.Info("listening on ", s.Addr())
			if err := s.Serve(); !errors.Is(err, http.ErrServerClosed) {
				log.Error(err)
			}
		}()
	}

	if p.srvProfiling != nil {
		_ = p.srvProfiling.Close()
		p.srvProfiling = nil
	}
	if cfg.Profiling != nil {
		addr := cfg.Profiling.Addr
		if addr == "" {
			addr = ":6060"
		}
		s := &http.Server{
			Addr: addr,
		}
		p.srvProfiling = s

		go func() {
			defer func() { _ = s.Close() }()

			log := logger.Default().WithFields(map[string]any{"kind": "service", "service": "@profiling"})

			log.Info("listening on ", addr)
			if err := s.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
				log.Error(err)
			}
		}()
	}

	// Build and start greyproxy service if configured
	if p.srvGreyproxy == nil {
		if err := p.buildGreyproxyService(); err != nil {
			logger.Default().Warnf("greyproxy: %v", err)
		}
	}

	return nil
}

func (p *program) Stop(s service.Service) error {
	if p.cancel != nil {
		p.cancel()
	}

	for name, srv := range registry.ServiceRegistry().GetAll() {
		_ = srv.Close()
		logger.Default().Debugf("service %s shutdown", name)
	}

	if p.srvMetrics != nil {
		_ = p.srvMetrics.Close()
		logger.Default().Debug("service @metrics shutdown")
	}
	if p.srvProfiling != nil {
		_ = p.srvProfiling.Close()
		logger.Default().Debug("service @profiling shutdown")
	}
	if p.mwCancel != nil {
		p.mwCancel()
	}
	if p.credStoreCancel != nil {
		p.credStoreCancel()
	}
	if p.assemblerCancel != nil {
		p.assemblerCancel()
	}
	if p.srvGreyproxy != nil {
		_ = p.srvGreyproxy.Close()
		logger.Default().Debug("service @greyproxy shutdown")
	}

	return nil
}

func (p *program) reload(ctx context.Context) {
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGHUP)

	for {
		select {
		case <-c:
			if err := p.reloadConfig(); err != nil {
				logger.Default().Error(err)
			} else {
				logger.Default().Info("config reloaded")
			}

		case <-ctx.Done():
			return
		}
	}
}

func (p *program) reloadConfig() error {
	cfg, err := parser.Parse()
	if err != nil {
		return err
	}
	injectCertPaths(cfg, greyproxyDataHome())
	injectSystemDNS(cfg)
	config.Set(cfg)

	if err := loader.Load(cfg); err != nil {
		return err
	}

	if err := p.run(cfg); err != nil {
		return err
	}

	// Record mtime of ca-cert.pem so CertReloadHandler can detect no-op calls.
	certFile := filepath.Join(greyproxyDataHome(), "ca-cert.pem")
	if info, err := os.Stat(certFile); err == nil {
		p.certMtimeMu.Lock()
		p.certMtime = info.ModTime()
		p.certMtimeMu.Unlock()
	}

	return nil
}

func (p *program) buildGreyproxyService() error {
	// Read greyproxy config from the same config file using viper
	var gaCfg greyproxy.Config
	if err := viper.UnmarshalKey("greyproxy", &gaCfg); err != nil {
		return nil // No greyproxy section, skip silently
	}
	if gaCfg.Addr == "" {
		return nil // Not configured
	}

	if gaCfg.PathPrefix == "" {
		gaCfg.PathPrefix = "/"
	}
	if gaCfg.DB == "" {
		gaCfg.DB = filepath.Join(greyproxyDataHome(), "greyproxy.db")
	}
	if gaCfg.Auther == "" {
		gaCfg.Auther = "auther-0"
	}
	if gaCfg.Admission == "" {
		gaCfg.Admission = "admission-0"
	}
	if gaCfg.Bypass == "" {
		gaCfg.Bypass = "bypass-0"
	}
	if gaCfg.Resolver == "" {
		gaCfg.Resolver = "resolver-0"
	}

	applyDockerEnvOverrides(&gaCfg)

	log := logger.Default().WithFields(map[string]any{"kind": "service", "service": "@greyproxy"})

	// Create shared state (this also opens the DB)
	shared := &greyproxy_api.Shared{}

	// Create a temporary service to get DB, cache, bus
	tmpSvc, err := greyproxy.NewService(&gaCfg, nil)
	if err != nil {
		return err
	}

	shared.DB = tmpSvc.DB
	shared.Cache = tmpSvc.Cache
	shared.Bus = tmpSvc.Bus
	shared.Waiters = tmpSvc.Waiters
	shared.ConnTracker = greyproxy.NewConnTracker()
	shared.DataHome = greyproxyDataHome()

	// User settings (persisted to disk, merged with defaults from config).
	settingsPath := filepath.Join(greyproxyDataHome(), "settings.json")
	shared.Settings = greyproxy.NewSettingsManager(settingsPath, gaCfg.Notifications.Enabled)
	if err := shared.Settings.Load(); err != nil {
		log.Warnf("failed to load user settings: %v", err)
	}

	// Build dashboard URL for notification click-to-open.
	dashboardURL := "http://localhost" + gaCfg.Addr + strings.TrimRight(gaCfg.PathPrefix, "/") + "/pending"
	resolvedSettings := shared.Settings.Get()
	shared.Notifier = greyproxy.NewNotifier(shared.Bus, shared.DB, resolvedSettings.NotificationsEnabled, dashboardURL)

	// Wire settings changes back to the notifier.
	shared.Settings.OnNotificationsChanged(func(enabled bool) {
		shared.Notifier.SetEnabled(enabled)
	})

	// Wire MITM toggle: apply initial setting and listen for changes.
	gostx.SetGlobalMitmEnabled(resolvedSettings.MitmEnabled)
	shared.Settings.OnMitmChanged(func(enabled bool) {
		gostx.SetGlobalMitmEnabled(enabled)
	})

	// Initialize credential substitution encryption key and store
	encKey, newKey, err := greyproxy.LoadOrGenerateKey(greyproxyDataHome())
	if err != nil {
		log.Warnf("credential substitution disabled: %v", err)
	} else {
		shared.EncryptionKey = encKey
		credStore, err := greyproxy.NewCredentialStore(shared.DB, encKey, shared.Bus)
		if err != nil {
			log.Warnf("credential store init failed: %v", err)
		} else {
			shared.CredentialStore = credStore
			if newKey {
				if sessions, globals, err := credStore.PurgeUnreadableCredentials(); err == nil && (sessions > 0 || globals > 0) {
					log.Infof("purged %d sessions and %d global credentials (new encryption key)", sessions, globals)
				}
			}
			credStoreCtx, credStoreCancel := context.WithCancel(context.Background())
			p.credStoreCancel = credStoreCancel
			credStore.StartCleanupLoop(credStoreCtx, 60*time.Second)
			// Wire credential substitution into the MITM pipeline
			gostx.SetGlobalCredentialSubstituter(func(req *http.Request) *gostx.CredentialSubstitutionInfo {
				result := credStore.SubstituteRequest(req)
				if result.Count == 0 {
					return nil
				}
				var sessionID string
				if len(result.SessionIDs) > 0 {
					sessionID = result.SessionIDs[0]
				}
				return &gostx.CredentialSubstitutionInfo{
					Labels:    result.Labels,
					SessionID: sessionID,
				}
			})
			log.Infof("credential store loaded: %d mappings from %d sessions", credStore.Size(), credStore.SessionCount())
		}
	}

	shared.ReloadCertFn = p.reloadConfig
	shared.CertMtimeFn = func() time.Time {
		p.certMtimeMu.Lock()
		defer p.certMtimeMu.Unlock()
		return p.certMtime
	}
	shared.Version = version

	// Collect listening ports for the health endpoint
	ports := make(map[string]int)
	if _, portStr, err := net.SplitHostPort(gaCfg.Addr); err == nil {
		if portNum, err := strconv.Atoi(portStr); err == nil {
			ports["api"] = portNum
		}
	}
	for name, svc := range registry.ServiceRegistry().GetAll() {
		if addr := svc.Addr(); addr != nil {
			if _, portStr, err := net.SplitHostPort(addr.String()); err == nil {
				if portNum, err := strconv.Atoi(portStr); err == nil {
					ports[name] = portNum
				}
			}
		}
	}
	shared.Ports = ports

	// Set the shared DNS cache so the DNS handler wrapper can populate it
	greyproxy_plugins.SetSharedDNSCache(shared.Cache)

	// Wire MITM HTTP round-trip hook to store transactions in the database
	gostx.SetGlobalMitmHook(func(info gostx.MitmRoundTripInfo) {
		host, portStr, _ := net.SplitHostPort(info.Host)
		if host == "" {
			host = info.Host
		}
		port, _ := strconv.Atoi(portStr)
		if port == 0 {
			port = 443
		}
		containerName, _ := greyproxy_plugins.ResolveIdentity(info.ContainerName, "")
		go func() {
			reqCT := info.RequestHeaders.Get("Content-Type")
			respCT := info.ResponseHeaders.Get("Content-Type")

			// Only store bodies for text-based content types, and decompress if needed
			var reqBody, respBody []byte
			if isTextContentType(reqCT) {
				reqBody = decompressBody(info.RequestBody, info.RequestHeaders.Get("Content-Encoding"))
			}
			if isTextContentType(respCT) {
				respBody = decompressBody(info.ResponseBody, info.ResponseHeaders.Get("Content-Encoding"))
			}

			// Redact sensitive headers before storing in the database
			redactor := shared.Settings.HeaderRedactor()
			redactedReqHeaders := redactor.Redact(info.RequestHeaders)
			redactedRespHeaders := redactor.Redact(info.ResponseHeaders)

			txn, err := greyproxy.CreateHttpTransaction(shared.DB, greyproxy.HttpTransactionCreateInput{
				ContainerName:          containerName,
				DestinationHost:        host,
				DestinationPort:        port,
				Method:                 info.Method,
				URL:                    "https://" + info.Host + info.URI,
				RequestHeaders:         redactedReqHeaders,
				RequestBody:            reqBody,
				RequestContentType:     reqCT,
				StatusCode:             info.StatusCode,
				ResponseHeaders:        redactedRespHeaders,
				ResponseBody:           respBody,
				ResponseContentType:    respCT,
				DurationMs:             info.DurationMs,
				Result:                 "auto",
				SubstitutedCredentials: info.SubstitutedCredentials,
				SessionID:              info.SessionID,
			})
			if err != nil {
				log.Warnf("failed to store HTTP transaction: %v", err)
				return
			}
			// Flush any middleware events stashed during the MITM response
			// cascade now that we have the http_transactions row ID.
			for _, ev := range middleware.DrainEvents(info.RequestID) {
				if werr := greyproxy.WriteMiddlewareEvent(shared.DB, greyproxy.MiddlewareEventInsert{
					TransactionID:   txn.ID,
					TransactionKind: "http",
					Sequence:        ev.Sequence,
					MiddlewareName:  ev.MiddlewareName,
					MiddlewareURL:   ev.MiddlewareURL,
					Hook:            ev.Hook,
					Action:          ev.Action,
					StatusCode:      ev.StatusCode,
					HeadersChanged:  ev.HeadersChanged,
					BodyRewritten:   ev.BodyRewritten,
					Tags:            ev.Tags,
					DurationMs:      ev.DurationMs,
				}); werr != nil {
					log.Warnf("failed to store middleware event: %v", werr)
				}
			}
			shared.Bus.Publish(greyproxy.Event{
				Type: greyproxy.EventTransactionNew,
				Data: txn.ToJSON(false),
			})
		}()
	})

	// Wire plain-HTTP round-trip hook to store transactions in the database.
	// Mirrors SetGlobalMitmHook above but for the non-MITM path (plain HTTP
	// upstreams, local HTTP servers, etc.). Without this, plain HTTP
	// traffic was invisible in Activity -- only the TCP connection rows
	// from request_logs would show, no HTTP detail or middleware badges.
	gostx.GlobalProxyRoundTripHook = func(ctx context.Context, info gostx.ProxyRoundTripInfo) {
		host, portStr, _ := net.SplitHostPort(info.Host)
		if host == "" {
			host = info.Host
		}
		port, _ := strconv.Atoi(portStr)
		if port == 0 {
			port = 80
		}
		containerName, _ := greyproxy_plugins.ResolveIdentity(info.ContainerName, "")

		reqCT := info.RequestHeaders.Get("Content-Type")
		respCT := info.ResponseHeaders.Get("Content-Type")
		var reqBody, respBody []byte
		if isTextContentType(reqCT) {
			reqBody = decompressBody(info.RequestBody, info.RequestHeaders.Get("Content-Encoding"))
		}
		if isTextContentType(respCT) {
			respBody = decompressBody(info.ResponseBody, info.ResponseHeaders.Get("Content-Encoding"))
		}

		redactor := shared.Settings.HeaderRedactor()
		redactedReqHeaders := redactor.Redact(info.RequestHeaders)
		redactedRespHeaders := redactor.Redact(info.ResponseHeaders)

		// URL as seen by the proxy. For a client using greyproxy as an HTTP
		// proxy, req.URL is absolute (e.g. "http://host/path"), so info.URL
		// already carries the scheme. If it somehow doesn't, fall back to
		// the host + URI shape MITM uses.
		url := info.URL
		if url == "" || !strings.HasPrefix(url, "http") {
			url = "http://" + info.Host + info.URL
		}

		txn, err := greyproxy.CreateHttpTransaction(shared.DB, greyproxy.HttpTransactionCreateInput{
			ContainerName:       containerName,
			DestinationHost:     host,
			DestinationPort:     port,
			Method:              info.Method,
			URL:                 url,
			RequestHeaders:      redactedReqHeaders,
			RequestBody:         reqBody,
			RequestContentType:  reqCT,
			StatusCode:          info.StatusCode,
			ResponseHeaders:     redactedRespHeaders,
			ResponseBody:        respBody,
			ResponseContentType: respCT,
			DurationMs:          info.DurationMs,
			Result:              "auto",
		})
		if err != nil {
			log.Warnf("failed to store plain-HTTP transaction: %v", err)
			return
		}
		// Flush middleware events stashed during the plain-HTTP cascade.
		for _, ev := range middleware.DrainEvents(info.RequestID) {
			if werr := greyproxy.WriteMiddlewareEvent(shared.DB, greyproxy.MiddlewareEventInsert{
				TransactionID:   txn.ID,
				TransactionKind: "http",
				Sequence:        ev.Sequence,
				MiddlewareName:  ev.MiddlewareName,
				MiddlewareURL:   ev.MiddlewareURL,
				Hook:            ev.Hook,
				Action:          ev.Action,
				StatusCode:      ev.StatusCode,
				HeadersChanged:  ev.HeadersChanged,
				BodyRewritten:   ev.BodyRewritten,
				Tags:            ev.Tags,
				DurationMs:      ev.DurationMs,
			}); werr != nil {
				log.Warnf("failed to store middleware event: %v", werr)
			}
		}
		shared.Bus.Publish(greyproxy.Event{
			Type: greyproxy.EventTransactionNew,
			Data: txn.ToJSON(false),
		})
	}

	// Wire connection-finish hook to update log entries with MITM skip reason
	gostx.SetGlobalConnectionFinishHook(func(info gostx.ConnectionFinishInfo) {
		if info.MitmSkipReason == "" {
			return
		}
		host, portStr, _ := net.SplitHostPort(info.Host)
		if host == "" {
			host = info.Host
		}
		port, _ := strconv.Atoi(portStr)
		if port == 0 {
			port = 443
		}
		containerName, _ := greyproxy_plugins.ResolveIdentity(info.ContainerName, "")
		go func() {
			if err := greyproxy.UpdateLatestLogMitmSkipReason(shared.DB, containerName, host, port, info.MitmSkipReason); err != nil {
				log.Warnf("failed to update MITM skip reason: %v", err)
			}
		}()
	})

	// Wire WebSocket frame hook to store frames as transactions in the database
	gostx.SetGlobalMitmWebSocketFrameHook(func(info gostx.MitmWebSocketFrameInfo) {
		host, portStr, _ := net.SplitHostPort(info.Host)
		if host == "" {
			host = info.Host
		}
		port, _ := strconv.Atoi(portStr)
		if port == 0 {
			port = 443
		}
		containerName, _ := greyproxy_plugins.ResolveIdentity(info.ContainerName, "")
		go func() {
			if len(info.Payload) == 0 {
				return
			}
			payload := info.Payload
			// If RSV1 is set, the frame uses permessage-deflate compression.
			// Decompress without context takeover (append sync tail first).
			if info.Rsv1 {
				decompressed, err := decompressWebSocketFrame(payload)
				if err != nil {
					log.Debugf("ws frame decompress failed (rsv1=%v from=%s): %v", info.Rsv1, info.From, err)
				} else {
					payload = decompressed
				}
			}
			method := "WS_REQ"
			if info.From == "server" {
				method = "WS_RESP"
			}
			txn, err := greyproxy.CreateHttpTransaction(shared.DB, greyproxy.HttpTransactionCreateInput{
				ContainerName:   containerName,
				DestinationHost: host,
				DestinationPort: port,
				Method:          method,
				URL:             "wss://" + info.Host + info.URI,
				RequestBody:     payload,
				StatusCode:      101,
				Result:          "auto",
			})
			if err != nil {
				log.Warnf("failed to store WebSocket frame: %v", err)
				return
			}
			shared.Bus.Publish(greyproxy.Event{
				Type: greyproxy.EventTransactionNew,
				Data: txn.ToJSON(false),
			})
		}()
	})

	// Wire MITM request-level hold hook: evaluate destination-level rules
	gostx.SetGlobalMitmHoldHook(func(ctx context.Context, info gostx.MitmRequestHoldInfo) error {
		host, portStr, _ := net.SplitHostPort(info.Host)
		if host == "" {
			host = info.Host
		}
		port, _ := strconv.Atoi(portStr)
		if port == 0 {
			port = 443
		}
		containerName, _ := greyproxy_plugins.ResolveIdentity(info.ContainerName, "")

		// Resolve hostname from cache
		resolvedHostname := shared.Cache.ResolveIP(host)
		if resolvedHostname == "" {
			resolvedHostname = host
		}

		rule := greyproxy.FindMatchingRule(shared.DB, containerName, host, port, resolvedHostname)
		if rule != nil && rule.Action == "deny" {
			return gostx.ErrRequestDenied
		}
		return nil
	})

	// Endpoint registry (LLM endpoint → decoder mapping). Created here
	// rather than next to the assembler below so the middleware hooks can
	// consult it for the `llm` filter. The same instance is reused by the
	// assembler, so toggling a rule in the UI affects both paths atomically.
	endpointRegistry := greyproxy.NewEndpointRegistry(shared.DB)

	// Wire middleware WebSocket clients if configured. Multiple middlewares
	// cascade in declaration order: each sees the previous one's output as
	// its input; deny/block short-circuits the chain.
	mwConfigs := buildMiddlewareConfigs(middlewareURLFlags, middlewareCmdFlags, gaCfg.Middlewares)
	if len(mwConfigs) > 0 {
		mwCtx, mwCancel := context.WithCancel(context.Background())
		p.mwCancel = mwCancel

		type clientHook struct {
			client  *middleware.Client
			url     string
			name    string // friendly name from hello (may be "")
			filters *middleware.HookFilter
		}

		// Start one client per config entry, in order.
		clients := make([]*middleware.Client, 0, len(mwConfigs))
		clientURLs := make([]string, 0, len(mwConfigs))
		for _, cfg := range mwConfigs {
			c := middleware.New(cfg)
			go func() { _ = c.Start(mwCtx) }()
			clients = append(clients, c)
			clientURLs = append(clientURLs, cfg.URL)
		}

		// Per hook type, collect the clients that declared that hook.
		var reqHooks, respHooks []clientHook
		for i, c := range clients {
			specs := c.HookSpecs() // blocks briefly for hello exchange
			name := c.Name()
			log.Infof("middleware connected: name=%q endpoint=%s transport=%s hooks=%d max_body_bytes=%d",
				name, c.URL(), c.Kind(), len(specs), c.MaxBodyBytes())
			for j := range specs {
				ch := clientHook{client: c, url: clientURLs[i], name: name, filters: specs[j].Filters}
				switch specs[j].Type {
				case "http-request":
					reqHooks = append(reqHooks, ch)
				case "http-response":
					respHooks = append(respHooks, ch)
				}
			}
		}

		// Expose the live middleware list to /api/middlewares. The closure
		// reads each client on every call so Connected / ProtocolVersion
		// stay fresh as reconnects happen.
		shared.MiddlewareStatusesFn = func() []greyproxy.MiddlewareStatus {
			out := make([]greyproxy.MiddlewareStatus, 0, len(clients))
			for _, c := range clients {
				hookNames := make([]string, 0, 2)
				for _, s := range c.HookSpecs() {
					hookNames = append(hookNames, s.Type)
				}
				out = append(out, greyproxy.MiddlewareStatus{
					URL:             c.URL(),
					Kind:            c.Kind(),
					Name:            c.Name(),
					Connected:       c.IsConnected(),
					ProtocolVersion: c.ProtocolVersion(),
					Hooks:           hookNames,
					MaxBodyBytes:    c.MaxBodyBytes(),
					TimeoutMs:       c.TimeoutMs(),
					OnDisconnect:    c.OnDisconnect(),
				})
			}
			return out
		}

		// truncateBody uses the smallest max_body_bytes across all clients
		// that declared a limit. 0 = no limit.
		truncateBody := func(body []byte) []byte {
			var max int64
			for _, c := range clients {
				m := c.MaxBodyBytes()
				if m > 0 && (max == 0 || m < max) {
					max = m
				}
			}
			if max > 0 && int64(len(body)) > max {
				return nil
			}
			return body
		}

		// Build the shared cascade hook list: both plain-HTTP and MITM
		// request hooks iterate the same reqHooks slice; same for respHooks.
		cascadeReq := make([]middleware.CascadeHook, 0, len(reqHooks))
		for _, h := range reqHooks {
			cascadeReq = append(cascadeReq, middleware.CascadeHook{Client: h.client, URL: h.url, Name: h.name, Filters: h.filters})
		}
		cascadeResp := make([]middleware.CascadeHook, 0, len(respHooks))
		for _, h := range respHooks {
			cascadeResp = append(cascadeResp, middleware.CascadeHook{Client: h.client, URL: h.url, Name: h.name, Filters: h.filters})
		}

		// ---- Plain HTTP request cascade ---------------------------------
		if len(cascadeReq) > 0 {
			gostx.GlobalProxyRequestHook = func(ctx context.Context, req *http.Request, container string) (context.Context, *gostx.ProxyRequestDecision) {
				body, _ := io.ReadAll(req.Body)
				req.Body = io.NopCloser(bytes.NewReader(body))
				// Stash the captured body so the response cascade can
				// include it in ResponseMsg.RequestBody.
				ctx = middleware.WithRequestBody(ctx, body)

				res := runRequestCascade(ctx, cascadeReq, req, container, false, "http-request", &body, endpointRegistry, truncateBody)
				if res.Denied {
					return ctx, &gostx.ProxyRequestDecision{
						Deny:       true,
						StatusCode: res.DenyStatus,
						DenyBody:   string(res.DenyBody),
					}
				}
				return ctx, nil
			}

			// ---- MITM request cascade -----------------------------------
			gostx.SetGlobalMitmRequestMiddlewareHook(func(ctx context.Context, req *http.Request, container string) error {
				body, _ := io.ReadAll(req.Body)
				req.Body = io.NopCloser(bytes.NewReader(body))

				res := runRequestCascade(ctx, cascadeReq, req, container, true, "mitm-request", &body, endpointRegistry, truncateBody)
				if res.Denied {
					return gostx.ErrRequestDenied
				}
				return nil
			})
		}

		// ---- Plain HTTP response cascade --------------------------------
		if len(cascadeResp) > 0 {
			gostx.GlobalProxyResponseHook = func(ctx context.Context, req *http.Request, resp *http.Response, container string) *gostx.ProxyResponseDecision {
				reqBody := middleware.RequestBodyFromContext(ctx)
				respBody, _ := io.ReadAll(resp.Body)
				resp.Body = io.NopCloser(bytes.NewReader(respBody))

				res := runResponseCascade(ctx, cascadeResp, responseCascadeInput{
					Host: req.Host, Method: req.Method, URI: req.RequestURI,
					RequestHeaders: req.Header.Clone(), RequestBody: reqBody,
					Status: resp.StatusCode, Headers: resp.Header.Clone(), Body: respBody,
					Container: container, TLS: false, HookLabel: "http-response",
				}, endpointRegistry, truncateBody)

				if res.Blocked {
					return &gostx.ProxyResponseDecision{
						Block:      true,
						StatusCode: res.BlockStatus,
						BlockBody:  string(res.BlockBody),
					}
				}
				if !res.Rewritten {
					return nil
				}
				return &gostx.ProxyResponseDecision{
					NewStatusCode: res.Status,
					NewHeaders:    res.Headers,
					NewBody:       res.Body,
				}
			}

			// ---- MITM response cascade ----------------------------------
			gostx.SetGlobalMitmResponseHook(func(ctx context.Context, info gostx.MitmRoundTripInfo) *gostx.MitmResponseDecision {
				res := runResponseCascade(ctx, cascadeResp, responseCascadeInput{
					Host: info.Host, Method: info.Method, URI: info.URI,
					RequestHeaders: info.RequestHeaders, RequestBody: info.RequestBody,
					Status: info.StatusCode, Headers: info.ResponseHeaders.Clone(), Body: info.ResponseBody,
					Container: info.ContainerName, TLS: true, HookLabel: "mitm-response",
					DurationMs: info.DurationMs, RequestID: info.RequestID,
				}, endpointRegistry, truncateBody)

				if res.Blocked {
					return &gostx.MitmResponseDecision{
						Block:      true,
						StatusCode: res.BlockStatus,
						BlockBody:  string(res.BlockBody),
					}
				}
				if !res.Rewritten {
					return nil
				}
				return &gostx.MitmResponseDecision{
					NewStatusCode: res.Status,
					NewHeaders:    res.Headers,
					NewBody:       res.Body,
				}
			})
		}
	}

	// Create the allow-all manager (in-memory, resets on restart).
	allowAllManager := greyproxy.NewAllowAllManager(shared.Bus)
	shared.AllowAll = allowAllManager
	if silentAllow {
		allowAllManager.Enable(0, greyproxy.SilentModeAllow) // duration=0 means until restart
	}

	// Initialize Docker resolver if configured.
	var dockerResolver greyproxy_plugins.ContainerResolver
	if gaCfg.Docker.Enabled {
		socketPath := gaCfg.Docker.Socket
		if socketPath == "" {
			socketPath = "/var/run/docker.sock"
		}
		cacheTTL := gaCfg.Docker.CacheTTL
		if cacheTTL == 0 {
			cacheTTL = 30 * time.Second
		}
		dockerResolver = greyproxy.NewDockerResolver(socketPath, cacheTTL)
		log.Infof("docker resolver enabled (socket=%s, cacheTTL=%s)", socketPath, cacheTTL)
	}

	// Create and register gost plugins
	autherPlugin := greyproxy_plugins.NewAuther()
	admissionPlugin := greyproxy_plugins.NewAdmission()
	bypassPlugin := greyproxy_plugins.NewBypass(shared.DB, shared.Cache, shared.Bus, shared.Waiters, shared.ConnTracker, dockerResolver, allowAllManager)
	sysDNS := systemDNSServers()[0]
	resolverPlugin := greyproxy_plugins.NewResolver(shared.Cache, sysDNS)
	log.Infof("dns resolver: upstream connections will resolve via %s", sysDNS)

	_ = registry.AutherRegistry().Register(gaCfg.Auther, autherPlugin)
	_ = registry.AdmissionRegistry().Register(gaCfg.Admission, admissionPlugin)
	_ = registry.BypassRegistry().Register(gaCfg.Bypass, bypassPlugin)
	_ = registry.ResolverRegistry().Register(gaCfg.Resolver, resolverPlugin)

	log.Infof("plugins registered: auther=%s admission=%s bypass=%s resolver=%s",
		gaCfg.Auther, gaCfg.Admission, gaCfg.Bypass, gaCfg.Resolver)

	// Build HTTP router with REST API + HTMX UI + WebSocket
	router, g := greyproxy_api.NewRouter(shared, gaCfg.PathPrefix)
	greyproxy_ui.RegisterPageRoutes(g, shared.DB, shared.Bus)
	greyproxy_ui.RegisterHTMXRoutes(g, shared.DB, shared.Bus, shared.Waiters, shared.ConnTracker)

	// Create the actual service
	svc := &greyproxy.Service{}
	*svc = *tmpSvc
	svc.SetHandler(router)

	p.srvGreyproxy = svc
	shared.Notifier.Start()

	// Start conversation assembler (dissects LLM API transactions into conversations)
	assemblerCtx, assemblerCancel := context.WithCancel(context.Background())
	p.assemblerCancel = assemblerCancel
	assembler := greyproxy.NewConversationAssembler(shared.DB, shared.Bus, endpointRegistry)
	assembler.SetEnabled(resolvedSettings.ConversationsEnabled)
	shared.Assembler = assembler
	go assembler.Start(assemblerCtx)

	shared.Settings.OnConversationsChanged(func(enabled bool) {
		assembler.SetEnabled(enabled)
	})

	go func() {
		log.Info("listening on ", svc.Addr())
		if err := svc.Serve(); !errors.Is(err, http.ErrServerClosed) {
			log.Error(err)
		}
	}()

	return nil
}

func buildMetricsService(cfg *config.MetricsConfig) (svccore.Service, error) {
	auther := auth_parser.ParseAutherFromAuth(cfg.Auth)
	if cfg.Auther != "" {
		auther = registry.AutherRegistry().Get(cfg.Auther)
	}

	network := "tcp"
	addr := cfg.Addr
	if strings.HasPrefix(addr, "unix://") {
		network = "unix"
		addr = strings.TrimPrefix(addr, "unix://")
	}
	return metrics.NewService(
		network, addr,
		metrics.PathOption(cfg.Path),
		metrics.AutherOption(auther),
	)
}

// greyproxyDataHome returns the directory for Greyproxy data files.
// Priority:
//  1. GREYPROXY_DATA_HOME env var
//  2. XDG_DATA_HOME/greyproxy env var
//  3. Platform default: ~/Library/Application Support/greyproxy (macOS)
//     or ~/.local/share/greyproxy (Linux/other)
//  4. Current directory (fallback if home dir is unavailable)
func greyproxyDataHome() string {
	if v := os.Getenv("GREYPROXY_DATA_HOME"); v != "" {
		return v
	}
	if v := os.Getenv("XDG_DATA_HOME"); v != "" {
		return filepath.Join(v, "greyproxy")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "."
	}
	if runtime.GOOS == "darwin" {
		return filepath.Join(home, "Library", "Application Support", "greyproxy")
	}
	return filepath.Join(home, ".local", "share", "greyproxy")
}

// isTextContentType returns true if the content type represents human-readable text.
func isTextContentType(ct string) bool {
	ct = strings.ToLower(ct)
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	ct = strings.TrimSpace(ct)
	switch {
	case strings.HasPrefix(ct, "text/"):
		return true
	case ct == "application/json",
		ct == "application/xml",
		ct == "application/javascript",
		ct == "application/x-javascript",
		ct == "application/ecmascript",
		ct == "application/x-www-form-urlencoded",
		ct == "application/graphql",
		ct == "application/soap+xml",
		ct == "application/xhtml+xml",
		ct == "application/x-ndjson":
		return true
	case strings.HasSuffix(ct, "+json"),
		strings.HasSuffix(ct, "+xml"):
		return true
	}
	return false
}

// decompressBody decompresses a body based on the Content-Encoding header.
// Returns the original body unchanged if encoding is identity/unknown or on error.
func decompressBody(body []byte, encoding string) []byte {
	if len(body) == 0 {
		return body
	}
	encoding = strings.ToLower(strings.TrimSpace(encoding))
	var reader io.ReadCloser
	var err error
	switch encoding {
	case "gzip", "x-gzip":
		reader, err = gzip.NewReader(bytes.NewReader(body))
	case "deflate":
		reader = flate.NewReader(bytes.NewReader(body))
	case "br":
		reader = io.NopCloser(brotli.NewReader(bytes.NewReader(body)))
	case "zstd":
		zr, zerr := zstd.NewReader(bytes.NewReader(body))
		if zerr != nil {
			return body
		}
		defer zr.Close()
		decoded, derr := io.ReadAll(zr)
		if derr != nil {
			return body
		}
		return decoded
	default:
		return body
	}
	if err != nil {
		return body
	}
	defer func() { _ = reader.Close() }()
	decoded, err := io.ReadAll(reader)
	if err != nil {
		return body
	}
	return decoded
}

// decompressWebSocketFrame decompresses a permessage-deflate WebSocket frame payload.
// The RSV1 bit signals per-frame deflate compression per RFC 7692.
//
// Go's compress/flate requires a BFINAL=1 block to terminate cleanly, unlike libz which
// handles SYNC_FLUSH (BFINAL=0) implicitly. The gorilla/websocket trick is to append both:
//   - 0x00 0x00 0xff 0xff  — the stripped SYNC_FLUSH terminator
//   - 0x01 0x00 0x00 0xff 0xff — a BFINAL=1 empty stored block to signal end-of-stream
func decompressWebSocketFrame(payload []byte) ([]byte, error) {
	const tail = "\x00\x00\xff\xff\x01\x00\x00\xff\xff"
	mr := io.MultiReader(bytes.NewReader(payload), strings.NewReader(tail))
	r := flate.NewReader(mr)
	defer func() { _ = r.Close() }()
	return io.ReadAll(r)
}

// applyDockerEnvOverrides configures Docker resolution from environment variables.
// Docker is disabled by default; use these env vars to opt in:
//
//   - GREYPROXY_DOCKER_ENABLED=true  → enable Docker resolution
//   - GREYPROXY_DOCKER_ENABLED=false → explicitly disable (default)
//   - GREYPROXY_DOCKER_SOCKET=<path> → socket path (default: /var/run/docker.sock)
func applyDockerEnvOverrides(cfg *greyproxy.Config) {
	switch os.Getenv("GREYPROXY_DOCKER_ENABLED") {
	case "true":
		cfg.Docker.Enabled = true
	case "false":
		cfg.Docker.Enabled = false
	}
	if v := os.Getenv("GREYPROXY_DOCKER_SOCKET"); v != "" {
		cfg.Docker.Socket = v
	}
}

// buildMiddlewareConfigs merges CLI flags and YAML config into the ordered
// list of middleware clients to instantiate. CLI entries come first, then
// YAML entries. CLI URL entries come before CLI command entries when
// operators mix the two flags; within each kind the declaration order on
// the command line is preserved. Defaults are resolved inside middleware.New
// (currently: timeout_ms=10000, on_disconnect=deny) — we leave TimeoutMs
// zero here so a single place owns the default, and YAML can override
// per-middleware.
//
// YAML entries with both url and command set are skipped with a warning:
// the two are mutually exclusive per the schema.
func buildMiddlewareConfigs(cliURLs, cliCmds []string, yamlEntries []greyproxy.MiddlewareConfig) []middleware.Config {
	out := make([]middleware.Config, 0, len(cliURLs)+len(cliCmds)+len(yamlEntries))
	for _, u := range cliURLs {
		if u == "" {
			continue
		}
		out = append(out, middleware.Config{URL: u})
	}
	for _, cmd := range cliCmds {
		if cmd == "" {
			continue
		}
		parts, err := splitCommand(cmd)
		if err != nil {
			logger.Default().Warnf("middleware --middleware-cmd %q: %v (skipping)", cmd, err)
			continue
		}
		out = append(out, middleware.Config{Command: parts})
	}
	for _, y := range yamlEntries {
		hasURL := y.URL != ""
		hasCmd := len(y.Command) > 0
		if hasURL && hasCmd {
			logger.Default().Warnf("middleware YAML entry has both url and command — skipping (%q / %v)", y.URL, y.Command)
			continue
		}
		if !hasURL && !hasCmd {
			continue
		}
		cfg := middleware.Config{
			URL:     y.URL,
			Command: y.Command,
			Name:    y.Name,
		}
		if y.TimeoutMs > 0 {
			cfg.TimeoutMs = y.TimeoutMs
		}
		if y.OnDisconnect != "" {
			cfg.OnDisconnect = y.OnDisconnect
		}
		cfg.AuthHeader = y.AuthHeader
		out = append(out, cfg)
	}
	return out
}

// splitCommand parses a command string into argv using shell-like rules
// (quoted segments preserved, backslash escapes respected) but without
// invoking a shell. This avoids the classic "spaces in paths need sh -c"
// trap while keeping the CLI ergonomic for simple cases.
//
// For anything complex (pipelines, redirects, env var expansion) the
// operator should invoke sh themselves: --middleware-cmd 'sh -c "FOO=bar ./mw"'.
func splitCommand(s string) ([]string, error) {
	var (
		out     []string
		cur     strings.Builder
		inQuote byte // 0, '\'', or '"'
		escaped bool
	)
	flush := func() {
		if cur.Len() > 0 {
			out = append(out, cur.String())
			cur.Reset()
		}
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case escaped:
			cur.WriteByte(c)
			escaped = false
		case c == '\\' && inQuote != '\'':
			escaped = true
		case inQuote != 0 && c == inQuote:
			inQuote = 0
		case inQuote == 0 && (c == '\'' || c == '"'):
			inQuote = c
		case inQuote == 0 && (c == ' ' || c == '\t'):
			flush()
		default:
			cur.WriteByte(c)
		}
	}
	if inQuote != 0 {
		return nil, fmt.Errorf("unterminated quote %c", inQuote)
	}
	if escaped {
		return nil, fmt.Errorf("trailing backslash")
	}
	flush()
	if len(out) == 0 {
		return nil, fmt.Errorf("empty command")
	}
	return out, nil
}

// requestCascadeResult is the neutral outcome of runRequestCascade; the
// plain-HTTP and MITM entry points translate it into their respective
// transport-specific decision types.
type requestCascadeResult struct {
	Denied     bool
	DenyStatus int
	DenyBody   []byte
}

// responseCascadeInput bundles the per-request state both response cascades
// need, so runResponseCascade can be transport-agnostic.
type responseCascadeInput struct {
	Host, Method, URI string
	RequestHeaders    http.Header
	RequestBody       []byte
	Status            int
	Headers           http.Header // working copy the cascade mutates
	Body              []byte      // working copy
	Container         string
	TLS               bool
	HookLabel         string // "http-response" | "mitm-response"
	DurationMs        int64
	RequestID         string // only set on MITM path; plain HTTP reads ctx
}

type responseCascadeResult struct {
	Blocked     bool
	BlockStatus int
	BlockBody   []byte
	Rewritten   bool
	Status      int
	Headers     http.Header
	Body        []byte
}

// runRequestCascade walks the request hooks in order. It mutates req's
// headers/body in place on rewrite (honouring the rewrite-header denylist),
// short-circuits on the first deny, and stashes an Activity event for every
// decision with side effects (deny/rewrite or tagged allow/passthrough).
//
// bodyPtr is *[]byte so a rewrite step can update the caller's view of the
// body without the caller having to re-read req.Body.
func runRequestCascade(
	ctx context.Context,
	hooks []middleware.CascadeHook,
	req *http.Request,
	container string,
	tls bool,
	hookLabel string,
	bodyPtr *[]byte,
	registry *greyproxy.EndpointRegistry,
	truncate func([]byte) []byte,
) requestCascadeResult {
	requestID := gostx.RequestIDFromContext(ctx)
	isLLM := registry.Match(req.URL.Path, req.Method, req.Host) != ""
	seq := 0
	log := logger.Default()

	for _, h := range hooks {
		ct := req.Header.Get("Content-Type")
		if !middleware.MatchesFilter(h.Filters, req.Host, req.URL.Path, req.Method, ct, container, tls, isLLM) {
			continue
		}
		preHeaders := req.Header.Clone()
		preBody := *bodyPtr
		msg := middleware.RequestMsg{
			Type: "http-request", ID: middleware.NewID(),
			Host: req.Host, Method: req.Method, URI: req.RequestURI,
			Proto: req.Proto, Headers: preHeaders,
			Body: truncate(*bodyPtr), Container: container, TLS: tls,
		}
		stepStart := time.Now()
		d := h.Client.Send(ctx, msg)
		stepMs := time.Since(stepStart).Milliseconds()

		if d.Fallback != "" {
			log.Warnf("middleware %s (%s): %s fallback action=%q", h.URL, hookLabel, d.Fallback, d.Action)
		}
		if !middleware.IsKnownAction(d.Action) {
			log.Warnf("middleware %s (%s): unknown action %q, treating as allow", h.URL, hookLabel, d.Action)
		}

		switch d.Action {
		case "deny":
			middleware.StashEvent(requestID, middleware.PendingEvent{
				Sequence: seq, MiddlewareName: h.Name, MiddlewareURL: h.URL, Hook: hookLabel,
				Action: "deny", StatusCode: d.StatusCode,
				Tags: d.Tags, DurationMs: stepMs, CreatedAt: time.Now(),
			})
			return requestCascadeResult{Denied: true, DenyStatus: d.StatusCode, DenyBody: d.Body}
		case "rewrite":
			if d.Body != nil {
				*bodyPtr = d.Body
				req.Body = io.NopCloser(bytes.NewReader(d.Body))
				req.ContentLength = int64(len(d.Body))
			}
			_, rejected := middleware.MergeRewriteHeaders(req.Header, d.Headers)
			if len(rejected) > 0 {
				log.Warnf("middleware %s (%s): rejected header rewrite for %v (hop-by-hop or auth)", h.URL, hookLabel, rejected)
			}
			middleware.StashEvent(requestID, middleware.PendingEvent{
				Sequence: seq, MiddlewareName: h.Name, MiddlewareURL: h.URL, Hook: hookLabel,
				Action: "rewrite", StatusCode: d.StatusCode,
				HeadersChanged: middleware.DiffHeaderNames(preHeaders, req.Header),
				BodyRewritten:  middleware.BodyChanged(preBody, d.Body),
				Tags:           d.Tags, DurationMs: stepMs, CreatedAt: time.Now(),
			})
		default:
			// allow / passthrough / unknown: only stash if tags were emitted.
			if len(d.Tags) > 0 {
				action := "tagged-allow"
				if d.Action == "passthrough" {
					action = "tagged-passthrough"
				}
				middleware.StashEvent(requestID, middleware.PendingEvent{
					Sequence: seq, MiddlewareName: h.Name, MiddlewareURL: h.URL, Hook: hookLabel,
					Action: action, Tags: d.Tags,
					DurationMs: stepMs, CreatedAt: time.Now(),
				})
			}
		}
		seq++
	}
	return requestCascadeResult{}
}

// runResponseCascade walks response hooks in order. It mutates the working
// copies on in.Headers/in.Body on rewrite, short-circuits on block, and
// returns the accumulated state. Decompression for the middleware's view of
// the body happens per step (middleware may rewrite and leave an older
// Content-Encoding in place; decompress guards against the next step trying
// to gunzip plaintext).
func runResponseCascade(
	ctx context.Context,
	hooks []middleware.CascadeHook,
	in responseCascadeInput,
	registry *greyproxy.EndpointRegistry,
	truncate func([]byte) []byte,
) responseCascadeResult {
	requestID := in.RequestID
	if requestID == "" {
		requestID = gostx.RequestIDFromContext(ctx)
	}
	isLLM := registry.Match(in.URI, in.Method, in.Host) != ""
	seq := 0
	log := logger.Default()

	workBody := in.Body
	workStatus := in.Status
	workHeaders := in.Headers
	rewritten := false

	for _, h := range hooks {
		respCT := workHeaders.Get("Content-Type")
		if !middleware.MatchesFilter(h.Filters, in.Host, in.URI, in.Method, respCT, in.Container, in.TLS, isLLM) {
			continue
		}
		mwBody := truncate(workBody)
		mwBody, _ = middleware.DecompressBody(mwBody, workHeaders.Get("Content-Encoding"))
		preHeaders := workHeaders.Clone()
		preBody := workBody
		msg := middleware.ResponseMsg{
			Type: "http-response", ID: middleware.NewID(),
			Host: in.Host, Method: in.Method, URI: in.URI,
			StatusCode:      workStatus,
			RequestHeaders:  in.RequestHeaders,
			RequestBody:     truncate(in.RequestBody),
			ResponseHeaders: preHeaders,
			ResponseBody:    mwBody,
			Container:       in.Container,
			DurationMs:      in.DurationMs,
		}
		stepStart := time.Now()
		d := h.Client.Send(ctx, msg)
		stepMs := time.Since(stepStart).Milliseconds()

		if d.Fallback != "" {
			log.Warnf("middleware %s (%s): %s fallback action=%q", h.URL, in.HookLabel, d.Fallback, d.Action)
		}
		if !middleware.IsKnownAction(d.Action) {
			log.Warnf("middleware %s (%s): unknown action %q, treating as passthrough", h.URL, in.HookLabel, d.Action)
		}

		switch d.Action {
		case "block":
			middleware.StashEvent(requestID, middleware.PendingEvent{
				Sequence: seq, MiddlewareName: h.Name, MiddlewareURL: h.URL, Hook: in.HookLabel,
				Action: "block", StatusCode: d.StatusCode,
				Tags: d.Tags, DurationMs: stepMs, CreatedAt: time.Now(),
			})
			return responseCascadeResult{Blocked: true, BlockStatus: d.StatusCode, BlockBody: d.Body}
		case "rewrite":
			rewritten = true
			if d.StatusCode != 0 {
				workStatus = d.StatusCode
			}
			if d.Body != nil {
				workBody = d.Body
				// If the middleware supplied a fresh body, the old
				// Content-Encoding almost certainly no longer matches.
				// Strip it so downstream (and the next cascade step)
				// don't try to decompress plaintext.
				workHeaders.Del("Content-Encoding")
			}
			_, rejected := middleware.MergeRewriteHeaders(workHeaders, d.Headers)
			if len(rejected) > 0 {
				log.Warnf("middleware %s (%s): rejected header rewrite for %v (hop-by-hop or auth)", h.URL, in.HookLabel, rejected)
			}
			middleware.StashEvent(requestID, middleware.PendingEvent{
				Sequence: seq, MiddlewareName: h.Name, MiddlewareURL: h.URL, Hook: in.HookLabel,
				Action: "rewrite", StatusCode: d.StatusCode,
				HeadersChanged: middleware.DiffHeaderNames(preHeaders, workHeaders),
				BodyRewritten:  middleware.BodyChanged(preBody, d.Body),
				Tags:           d.Tags, DurationMs: stepMs, CreatedAt: time.Now(),
			})
		default:
			if len(d.Tags) > 0 {
				action := "tagged-allow"
				if d.Action == "passthrough" {
					action = "tagged-passthrough"
				}
				middleware.StashEvent(requestID, middleware.PendingEvent{
					Sequence: seq, MiddlewareName: h.Name, MiddlewareURL: h.URL, Hook: in.HookLabel,
					Action: action, Tags: d.Tags,
					DurationMs: stepMs, CreatedAt: time.Now(),
				})
			}
		}
		seq++
	}

	return responseCascadeResult{
		Rewritten: rewritten,
		Status:    workStatus,
		Headers:   workHeaders,
		Body:      workBody,
	}
}
