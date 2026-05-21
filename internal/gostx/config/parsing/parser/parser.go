package parser

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"strings"

	"github.com/greyhavenhq/greyproxy/internal/gostcore/logger"
	"github.com/greyhavenhq/greyproxy/internal/gostx/config"
	"github.com/greyhavenhq/greyproxy/internal/gostx/config/cmd"
	xmd "github.com/greyhavenhq/greyproxy/internal/gostx/metadata"
	mdutil "github.com/greyhavenhq/greyproxy/internal/gostx/metadata/util"
)

var (
	defaultParser = &parser{}
)

func Init(args Args) {
	defaultParser = &parser{
		args: args,
	}
}

func Parse() (*config.Config, error) {
	return defaultParser.Parse()
}

type Args struct {
	CfgFile       string
	DefaultConfig []byte // embedded default config (used when CfgFile is empty)
	Services      []string
	Nodes         []string
	Debug         bool
	Trace         bool
	MetricsAddr   string
	// Host overrides the bind interface for every listener that was
	// specified as a bare port (":43080" / "43080"). When empty, the
	// top-level `host:` field from the config is used; if that's empty
	// too, DefaultHost (127.0.0.1) wins. Explicit hosts in YAML or in
	// -L addresses are left alone.
	Host string
}

type parser struct {
	args Args
}

func (p *parser) Parse() (*config.Config, error) {
	cfg := &config.Config{}

	if cfgFile := strings.TrimSpace(p.args.CfgFile); cfgFile != "" {
		if cfgFile == "-" { // stdin
			br := bufio.NewReader(os.Stdin)
			b, err := br.Peek(1)
			if err != nil {
				return nil, err
			}
			if b[0] == '{' {
				if err := cfg.Read(br, "json"); err != nil {
					return nil, err
				}
			} else {
				if err := cfg.Read(br, "yaml"); err != nil {
					return nil, err
				}
			}
		} else if strings.HasPrefix(cfgFile, "{") && strings.HasSuffix(cfgFile, "}") { // inline
			if err := json.Unmarshal([]byte(cfgFile), cfg); err != nil {
				return nil, err
			}
		} else {
			if err := cfg.ReadFile(cfgFile); err != nil { // file
				return nil, err
			}
		}
	} else if len(p.args.DefaultConfig) > 0 {
		// No -C flag: use the embedded default configuration.
		if err := cfg.Read(bytes.NewReader(p.args.DefaultConfig), "yaml"); err != nil {
			return nil, err
		}
	}

	cmdCfg, err := cmd.BuildConfigFromCmd(p.args.Services, p.args.Nodes)
	if err != nil {
		return nil, err
	}
	cfg = mergeConfig(cfg, cmdCfg)

	if len(cfg.Services) == 0 {
		if err := cfg.Load(); err != nil {
			return nil, err
		}
	}

	if v := os.Getenv("GOST_LOGGER_LEVEL"); v != "" {
		cfg.Log = &config.LogConfig{
			Level: v,
		}
	}
	if v := os.Getenv("GOST_METRICS"); v != "" {
		cfg.Metrics = &config.MetricsConfig{
			Addr: v,
		}
	}
	if v := os.Getenv("GOST_PROFILING"); v != "" {
		cfg.Profiling = &config.ProfilingConfig{
			Addr: v,
		}
	}

	if p.args.Debug || p.args.Trace {
		if cfg.Log == nil {
			cfg.Log = &config.LogConfig{}
		}

		cfg.Log.Level = string(logger.DebugLevel)
		if p.args.Trace {
			cfg.Log.Level = string(logger.TraceLevel)
		}
	}

	if p.args.MetricsAddr != "" {
		cfg.Metrics = &config.MetricsConfig{
			Addr: p.args.MetricsAddr,
		}
		if url, _ := cmd.Norm(p.args.MetricsAddr); url != nil {
			cfg.Metrics.Addr = url.Host
			if url.User != nil {
				username := url.User.Username()
				password, _ := url.User.Password()
				cfg.Metrics.Auth = &config.AuthConfig{
					Username: username,
					Password: password,
				}
			}
			m := map[string]any{}
			for k, v := range url.Query() {
				if len(v) > 0 {
					m[k] = v[0]
				}
			}
			md := xmd.NewMetadata(m)
			cfg.Metrics.Path = mdutil.GetString(md, "path")
		}
	}

	walkAddresses(cfg, ResolveHost(p.args.Host, cfg.Host))

	return cfg, nil
}

// ResolveHost returns the host that should be applied to bare listener
// addresses. Precedence: CLI flag > YAML top-level `host:` > DefaultHost.
func ResolveHost(flagHost, yamlHost string) string {
	if flagHost != "" {
		return flagHost
	}
	if yamlHost != "" {
		return yamlHost
	}
	return DefaultHost
}

func mergeConfig(cfg1, cfg2 *config.Config) *config.Config {
	if cfg1 == nil {
		return cfg2
	}
	if cfg2 == nil {
		return cfg1
	}

	cfg := &config.Config{
		Host:       cfg1.Host,
		Services:   append(cfg1.Services, cfg2.Services...),
		Authers:    append(cfg1.Authers, cfg2.Authers...),
		Admissions: append(cfg1.Admissions, cfg2.Admissions...),
		Bypasses:   append(cfg1.Bypasses, cfg2.Bypasses...),
		Resolvers:  append(cfg1.Resolvers, cfg2.Resolvers...),
		Hosts:      append(cfg1.Hosts, cfg2.Hosts...),
		Limiters:   append(cfg1.Limiters, cfg2.Limiters...),
		CLimiters:  append(cfg1.CLimiters, cfg2.CLimiters...),
		RLimiters:  append(cfg1.RLimiters, cfg2.RLimiters...),
		Loggers:    append(cfg1.Loggers, cfg2.Loggers...),
		TLS:        cfg1.TLS,
		Log:        cfg1.Log,
		Metrics:    cfg1.Metrics,
		Profiling:  cfg1.Profiling,
	}
	if cfg2.Host != "" {
		cfg.Host = cfg2.Host
	}
	if cfg2.TLS != nil {
		cfg.TLS = cfg2.TLS
	}
	if cfg2.Log != nil {
		cfg.Log = cfg2.Log
	}
	if cfg2.Metrics != nil {
		cfg.Metrics = cfg2.Metrics
	}
	if cfg2.Profiling != nil {
		cfg.Profiling = cfg2.Profiling
	}

	return cfg
}
