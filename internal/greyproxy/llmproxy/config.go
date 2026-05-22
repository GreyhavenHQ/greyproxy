package llmproxy

// SeedConfig is the YAML-side `llm:` block. It only ever populates an
// empty SQLite database on first start; after that, the database is the
// source of truth and the dashboard / management API drives changes.
// Subsequent runs with a non-empty database ignore this entirely.
//
// Phase 1 ships only the providers and models (alias) lists. redirects,
// guardrails, and auto-rules land in later phases and are documented here
// as placeholder fields so the YAML schema stays stable.
//
// Every field carries a `mapstructure` tag in addition to yaml/json:
// cmd/greyproxy loads this via viper.UnmarshalKey, which decodes through
// mapstructure (not the yaml library). Without explicit mapstructure tags,
// snake_case keys like `base_url` silently fail to bind to camelCase Go
// fields. See TestSeedConfig_ViperRoundTrip.
type SeedConfig struct {
	Providers  []SeedProvider  `yaml:"providers,omitempty" json:"providers,omitempty" mapstructure:"providers"`
	Models     []SeedAlias     `yaml:"models,omitempty" json:"models,omitempty" mapstructure:"models"`
	Redirects  []SeedRedirect  `yaml:"redirects,omitempty" json:"redirects,omitempty" mapstructure:"redirects"`
	Guardrails []SeedGuardrail `yaml:"guardrails,omitempty" json:"guardrails,omitempty" mapstructure:"guardrails"`
}

// SeedProvider describes a single upstream LLM provider.
//
// `api_key` can be a literal value or `env:NAME` to resolve from the
// process environment at seed time. Empty key is permitted (useful for
// local-only providers like Ollama).
type SeedProvider struct {
	Name     string            `yaml:"name" json:"name" mapstructure:"name"`
	Type     string            `yaml:"type" json:"type" mapstructure:"type"` // openai | anthropic | openai-compat | openrouter
	BaseURL  string            `yaml:"base_url" json:"base_url" mapstructure:"base_url"`
	APIKey   string            `yaml:"api_key,omitempty" json:"api_key,omitempty" mapstructure:"api_key"`
	Enabled  *bool             `yaml:"enabled,omitempty" json:"enabled,omitempty" mapstructure:"enabled"`
	Metadata map[string]string `yaml:"metadata,omitempty" json:"metadata,omitempty" mapstructure:"metadata"`
}

// SeedAlias describes a single model alias. Target is `provider/model_id`
// — the public name (Name) is what clients reference; the proxy resolves
// it to the (provider, model_id) pair at request time.
type SeedAlias struct {
	Name      string   `yaml:"name" json:"name" mapstructure:"name"`
	Target    string   `yaml:"target,omitempty" json:"target,omitempty" mapstructure:"target"`
	Fallbacks []string `yaml:"fallbacks,omitempty" json:"fallbacks,omitempty" mapstructure:"fallbacks"`
	Enabled   *bool    `yaml:"enabled,omitempty" json:"enabled,omitempty" mapstructure:"enabled"`

	// Auto, when set, marks this alias as an auto-router. Phase 5+.
	Auto *SeedAuto `yaml:"auto,omitempty" json:"auto,omitempty" mapstructure:"auto"`
}

// SeedAuto holds the rule list for an auto-routing alias. Phase 5+.
type SeedAuto struct {
	Rules []map[string]any `yaml:"rules,omitempty" json:"rules,omitempty" mapstructure:"rules"`
}

// SeedRedirect — Phase 3 placeholder. The match clause and target string
// are stored verbatim and interpreted by the router when redirects ship.
type SeedRedirect struct {
	Priority int            `yaml:"priority,omitempty" json:"priority,omitempty" mapstructure:"priority"`
	Match    map[string]any `yaml:"match" json:"match" mapstructure:"match"`
	Target   string         `yaml:"target" json:"target" mapstructure:"target"`
	Enabled  *bool          `yaml:"enabled,omitempty" json:"enabled,omitempty" mapstructure:"enabled"`
}

// SeedGuardrail — Phase 4 placeholder.
type SeedGuardrail struct {
	Name    string         `yaml:"name" json:"name" mapstructure:"name"`
	Mode    string         `yaml:"mode" json:"mode" mapstructure:"mode"`
	Type    string         `yaml:"type" json:"type" mapstructure:"type"`
	Config  map[string]any `yaml:"config,omitempty" json:"config,omitempty" mapstructure:"config"`
	Pattern string         `yaml:"pattern,omitempty" json:"pattern,omitempty" mapstructure:"pattern"`
	Action  string         `yaml:"action,omitempty" json:"action,omitempty" mapstructure:"action"`
	Replace string         `yaml:"replace,omitempty" json:"replace,omitempty" mapstructure:"replace"`
	URL     string         `yaml:"url,omitempty" json:"url,omitempty" mapstructure:"url"`

	Priority int   `yaml:"priority,omitempty" json:"priority,omitempty" mapstructure:"priority"`
	Enabled  *bool `yaml:"enabled,omitempty" json:"enabled,omitempty" mapstructure:"enabled"`
}
