package main

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"context"
	"errors"
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
			shared.Bus.Publish(greyproxy.Event{
				Type: greyproxy.EventTransactionNew,
				Data: txn.ToJSON(false),
			})
		}()
	})

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
	endpointRegistry := greyproxy.NewEndpointRegistry(shared.DB)
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
