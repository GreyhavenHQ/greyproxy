package llmproxy

// SeedConfig is the YAML-side `llm:` block. It only ever populates an
// empty SQLite database on first start; after that, the database is the
// source of truth and the dashboard / management API drives changes.
// Subsequent runs with a non-empty database ignore this entirely.
//
// Phase 1 ships only the providers and models (alias) lists. redirects,
// guardrails, and auto-rules land in later phases and are documented here
// as placeholder fields so the YAML schema stays stable.
type SeedConfig struct {
	Providers  []SeedProvider  `yaml:"providers,omitempty" json:"providers,omitempty"`
	Models     []SeedAlias     `yaml:"models,omitempty" json:"models,omitempty"`
	Redirects  []SeedRedirect  `yaml:"redirects,omitempty" json:"redirects,omitempty"`
	Guardrails []SeedGuardrail `yaml:"guardrails,omitempty" json:"guardrails,omitempty"`
}

// SeedProvider describes a single upstream LLM provider.
//
// `api_key` can be a literal value or `env:NAME` to resolve from the
// process environment at seed time. Empty key is permitted (useful for
// local-only providers like Ollama).
type SeedProvider struct {
	Name     string            `yaml:"name" json:"name"`
	Type     string            `yaml:"type" json:"type"` // openai | anthropic | openai-compat | openrouter
	BaseURL  string            `yaml:"base_url" json:"base_url"`
	APIKey   string            `yaml:"api_key,omitempty" json:"api_key,omitempty"`
	Enabled  *bool             `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	Metadata map[string]string `yaml:"metadata,omitempty" json:"metadata,omitempty"`
}

// SeedAlias describes a single model alias. Target is `provider/model_id`
// — the public name (Name) is what clients reference; the proxy resolves
// it to the (provider, model_id) pair at request time.
type SeedAlias struct {
	Name      string   `yaml:"name" json:"name"`
	Target    string   `yaml:"target,omitempty" json:"target,omitempty"`
	Fallbacks []string `yaml:"fallbacks,omitempty" json:"fallbacks,omitempty"`
	Enabled   *bool    `yaml:"enabled,omitempty" json:"enabled,omitempty"`

	// Auto, when set, marks this alias as an auto-router. Phase 5+.
	Auto *SeedAuto `yaml:"auto,omitempty" json:"auto,omitempty"`
}

// SeedAuto holds the rule list for an auto-routing alias. Phase 5+.
type SeedAuto struct {
	Rules []map[string]any `yaml:"rules,omitempty" json:"rules,omitempty"`
}

// SeedRedirect — Phase 3 placeholder. The match clause and target string
// are stored verbatim and interpreted by the router when redirects ship.
type SeedRedirect struct {
	Priority int            `yaml:"priority,omitempty" json:"priority,omitempty"`
	Match    map[string]any `yaml:"match" json:"match"`
	Target   string         `yaml:"target" json:"target"`
	Enabled  *bool          `yaml:"enabled,omitempty" json:"enabled,omitempty"`
}

// SeedGuardrail — Phase 4 placeholder.
type SeedGuardrail struct {
	Name    string         `yaml:"name" json:"name"`
	Mode    string         `yaml:"mode" json:"mode"`
	Type    string         `yaml:"type" json:"type"`
	Config  map[string]any `yaml:"config,omitempty" json:"config,omitempty"`
	Pattern string         `yaml:"pattern,omitempty" json:"pattern,omitempty"`
	Action  string         `yaml:"action,omitempty" json:"action,omitempty"`
	Replace string         `yaml:"replace,omitempty" json:"replace,omitempty"`
	URL     string         `yaml:"url,omitempty" json:"url,omitempty"`

	Priority int   `yaml:"priority,omitempty" json:"priority,omitempty"`
	Enabled  *bool `yaml:"enabled,omitempty" json:"enabled,omitempty"`
}
