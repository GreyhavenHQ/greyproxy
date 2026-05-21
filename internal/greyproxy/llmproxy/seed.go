package llmproxy

import (
	"fmt"
	"os"
	"strings"
)

// Seed inserts the YAML-provided providers and aliases into an empty
// database. Returns the number of providers and aliases written. If
// either table already has rows, the call is a no-op — the database is
// authoritative after first start.
//
// Phase 1 ignores Redirects and Guardrails in the SeedConfig (those
// tables don't exist yet); they'll be picked up in Phase 3 / Phase 4.
func (s *Store) Seed(cfg SeedConfig) (providers, aliases int, err error) {
	provCount, err := s.countRows("llm_providers")
	if err != nil {
		return 0, 0, fmt.Errorf("count providers: %w", err)
	}
	aliasCount, err := s.countRows("llm_aliases")
	if err != nil {
		return 0, 0, fmt.Errorf("count aliases: %w", err)
	}
	if provCount > 0 || aliasCount > 0 {
		// Already seeded (or operator added rows via the dashboard). Don't
		// double-insert.
		return 0, 0, nil
	}

	// Insert providers first so aliases can reference their IDs.
	nameToID := make(map[string]int64, len(cfg.Providers))
	for _, p := range cfg.Providers {
		key := resolveAPIKey(p.APIKey)
		enabled := true
		if p.Enabled != nil {
			enabled = *p.Enabled
		}
		row, err := s.CreateProvider(ProviderInput{
			Name:     p.Name,
			Type:     p.Type,
			BaseURL:  p.BaseURL,
			APIKey:   key,
			Enabled:  &enabled,
			Metadata: p.Metadata,
		})
		if err != nil {
			return providers, aliases, fmt.Errorf("seed provider %q: %w", p.Name, err)
		}
		nameToID[p.Name] = row.ID
		providers++
	}

	for _, a := range cfg.Models {
		if a.Auto != nil {
			// Phase 5 territory; skip silently for now so the YAML can be
			// future-proofed without breaking Phase 1 startup.
			continue
		}
		providerName, modelID := splitTarget(a.Target)
		pid, ok := nameToID[providerName]
		if !ok {
			return providers, aliases, fmt.Errorf("seed alias %q: unknown provider %q", a.Name, providerName)
		}
		enabled := true
		if a.Enabled != nil {
			enabled = *a.Enabled
		}
		_, err := s.CreateAlias(AliasInput{
			Name:       a.Name,
			ProviderID: pid,
			ModelID:    modelID,
			Fallbacks:  a.Fallbacks,
			Enabled:    &enabled,
		})
		if err != nil {
			return providers, aliases, fmt.Errorf("seed alias %q: %w", a.Name, err)
		}
		aliases++
	}
	return providers, aliases, nil
}

func (s *Store) countRows(table string) (int, error) {
	var n int
	// Table name is constant — no SQL injection surface; sql.Open won't
	// allow parameter binding on table names anyway.
	err := s.db.ReadDB().QueryRow("SELECT COUNT(*) FROM " + table).Scan(&n)
	return n, err
}

// resolveAPIKey expands the env:NAME indirection. Other forms pass
// through verbatim so operators can supply literal keys if they want.
func resolveAPIKey(raw string) string {
	if !strings.HasPrefix(raw, "env:") {
		return raw
	}
	return os.Getenv(strings.TrimPrefix(raw, "env:"))
}

// splitTarget parses "provider/model_id" into its two parts. The model
// part may contain slashes (e.g. anthropic/claude-3.5-haiku@20241022) —
// only the first slash separates provider from model.
func splitTarget(target string) (provider, modelID string) {
	i := strings.IndexByte(target, '/')
	if i < 0 {
		return target, ""
	}
	return target[:i], target[i+1:]
}
