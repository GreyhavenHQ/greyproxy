package greyproxy

import (
	"database/sql"
	"fmt"
)

var migrations = []string{
	// Migration 1: Create rules table
	`CREATE TABLE IF NOT EXISTS rules (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		container_pattern TEXT NOT NULL,
		destination_pattern TEXT NOT NULL,
		port_pattern TEXT NOT NULL DEFAULT '*',
		rule_type TEXT NOT NULL DEFAULT 'permanent' CHECK (rule_type IN ('permanent', 'temporary')),
		action TEXT NOT NULL DEFAULT 'allow' CHECK (action IN ('allow', 'deny')),
		created_at DATETIME NOT NULL DEFAULT (datetime('now')),
		expires_at DATETIME,
		last_used_at DATETIME,
		created_by TEXT NOT NULL DEFAULT 'admin',
		notes TEXT,
		UNIQUE(container_pattern, destination_pattern, port_pattern, action)
	);
	CREATE INDEX IF NOT EXISTS idx_rules_container ON rules(container_pattern);
	CREATE INDEX IF NOT EXISTS idx_rules_destination ON rules(destination_pattern);
	CREATE INDEX IF NOT EXISTS idx_rules_expires ON rules(expires_at);`,

	// Migration 2: Create pending_requests table
	`CREATE TABLE IF NOT EXISTS pending_requests (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		container_name TEXT NOT NULL,
		container_id TEXT NOT NULL DEFAULT '',
		destination_host TEXT NOT NULL,
		destination_port INTEGER NOT NULL,
		resolved_hostname TEXT,
		first_seen DATETIME NOT NULL DEFAULT (datetime('now')),
		last_seen DATETIME NOT NULL DEFAULT (datetime('now')),
		attempt_count INTEGER NOT NULL DEFAULT 1,
		UNIQUE(container_name, destination_host, destination_port)
	);
	CREATE INDEX IF NOT EXISTS idx_pending_container ON pending_requests(container_name);
	CREATE INDEX IF NOT EXISTS idx_pending_last_seen ON pending_requests(last_seen);`,

	// Migration 3: Create request_logs table
	`CREATE TABLE IF NOT EXISTS request_logs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp DATETIME NOT NULL DEFAULT (datetime('now')),
		container_name TEXT NOT NULL,
		container_id TEXT,
		destination_host TEXT NOT NULL,
		destination_port INTEGER,
		resolved_hostname TEXT,
		method TEXT,
		result TEXT NOT NULL CHECK (result IN ('allowed', 'blocked')),
		rule_id INTEGER REFERENCES rules(id) ON DELETE SET NULL,
		response_time_ms INTEGER
	);
	CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON request_logs(timestamp);
	CREATE INDEX IF NOT EXISTS idx_logs_container ON request_logs(container_name);
	CREATE INDEX IF NOT EXISTS idx_logs_destination ON request_logs(destination_host);
	CREATE INDEX IF NOT EXISTS idx_logs_result ON request_logs(result);`,

	// Migration 4: Create http_transactions table for MITM-captured HTTP request/response data
	`CREATE TABLE IF NOT EXISTS http_transactions (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp DATETIME NOT NULL DEFAULT (datetime('now')),
		container_name TEXT NOT NULL,
		destination_host TEXT NOT NULL,
		destination_port INTEGER NOT NULL,

		method TEXT NOT NULL,
		url TEXT NOT NULL,
		request_headers TEXT,
		request_body BLOB,
		request_body_size INTEGER,
		request_content_type TEXT,

		status_code INTEGER,
		response_headers TEXT,
		response_body BLOB,
		response_body_size INTEGER,
		response_content_type TEXT,

		duration_ms INTEGER,
		rule_id INTEGER,
		result TEXT NOT NULL DEFAULT 'auto'
	);
	CREATE INDEX IF NOT EXISTS idx_http_transactions_ts ON http_transactions(timestamp);
	CREATE INDEX IF NOT EXISTS idx_http_transactions_dest ON http_transactions(destination_host, destination_port);`,

	// Migration 5: Create conversations and turns tables for LLM conversation dissection
	`CREATE TABLE IF NOT EXISTS conversations (
		id TEXT PRIMARY KEY,
		model TEXT,
		container_name TEXT,
		provider TEXT,
		started_at TEXT,
		ended_at TEXT,
		turn_count INTEGER DEFAULT 0,
		system_prompt TEXT,
		system_prompt_summary TEXT,
		parent_conversation_id TEXT,
		last_turn_has_response INTEGER DEFAULT 0,
		metadata_json TEXT,
		linked_subagents_json TEXT,
		request_ids_json TEXT,
		incomplete INTEGER DEFAULT 0,
		incomplete_reason TEXT,
		updated_at TEXT NOT NULL DEFAULT (datetime('now'))
	);
	CREATE INDEX IF NOT EXISTS idx_conv_started ON conversations(started_at);
	CREATE INDEX IF NOT EXISTS idx_conv_parent ON conversations(parent_conversation_id);
	CREATE INDEX IF NOT EXISTS idx_conv_provider ON conversations(provider);

	CREATE TABLE IF NOT EXISTS turns (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		conversation_id TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
		turn_number INTEGER NOT NULL,
		user_prompt TEXT,
		steps_json TEXT,
		api_calls_in_turn INTEGER DEFAULT 0,
		request_ids_json TEXT,
		timestamp TEXT,
		timestamp_end TEXT,
		duration_ms INTEGER,
		model TEXT,
		UNIQUE(conversation_id, turn_number)
	);
	CREATE INDEX IF NOT EXISTS idx_turns_conv ON turns(conversation_id);

	CREATE TABLE IF NOT EXISTS conversation_processing_state (
		key TEXT PRIMARY KEY,
		value TEXT NOT NULL
	);`,

	// Migration 6: Add conversation_id column to http_transactions for bidirectional linking
	`ALTER TABLE http_transactions ADD COLUMN conversation_id TEXT;
	CREATE INDEX IF NOT EXISTS idx_http_transactions_conv ON http_transactions(conversation_id);`,

	// Migration 7: Add mitm_skip_reason column to request_logs for tracking why MITM was skipped
	`ALTER TABLE request_logs ADD COLUMN mitm_skip_reason TEXT;`,

	// Migration 8: Create sessions and global_credentials tables for credential substitution
	`CREATE TABLE IF NOT EXISTS sessions (
		session_id       TEXT PRIMARY KEY,
		container_name   TEXT NOT NULL,
		mappings_enc     BLOB NOT NULL,
		labels_json      TEXT NOT NULL DEFAULT '{}',
		ttl_seconds      INTEGER NOT NULL DEFAULT 900,
		created_at       DATETIME NOT NULL DEFAULT (datetime('now')),
		expires_at       DATETIME NOT NULL,
		last_heartbeat   DATETIME NOT NULL DEFAULT (datetime('now')),
		substitution_count INTEGER NOT NULL DEFAULT 0
	);
	CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
	CREATE INDEX IF NOT EXISTS idx_sessions_container ON sessions(container_name);

	CREATE TABLE IF NOT EXISTS global_credentials (
		id              TEXT PRIMARY KEY,
		label           TEXT NOT NULL UNIQUE,
		placeholder     TEXT NOT NULL UNIQUE,
		value_enc       BLOB NOT NULL,
		value_preview   TEXT NOT NULL,
		created_at      DATETIME NOT NULL DEFAULT (datetime('now'))
	);`,

	// Migration 9: Add credential substitution tracking, session metadata, and transaction-session linking
	`ALTER TABLE http_transactions ADD COLUMN substituted_credentials TEXT DEFAULT NULL;
	ALTER TABLE http_transactions ADD COLUMN session_id TEXT DEFAULT NULL;
	CREATE INDEX IF NOT EXISTS idx_http_transactions_session ON http_transactions(session_id);
	ALTER TABLE sessions ADD COLUMN metadata_json TEXT NOT NULL DEFAULT '{}';`,
}

func runMigrations(db *sql.DB) error {
	// Create migrations tracking table
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
		version INTEGER PRIMARY KEY,
		applied_at DATETIME NOT NULL DEFAULT (datetime('now'))
	)`); err != nil {
		return fmt.Errorf("create migrations table: %w", err)
	}

	for i, m := range migrations {
		version := i + 1
		var count int
		if err := db.QueryRow("SELECT COUNT(*) FROM schema_migrations WHERE version = ?", version).Scan(&count); err != nil {
			return fmt.Errorf("check migration %d: %w", version, err)
		}
		if count > 0 {
			continue
		}

		if _, err := db.Exec(m); err != nil {
			return fmt.Errorf("run migration %d: %w", version, err)
		}
		if _, err := db.Exec("INSERT INTO schema_migrations (version) VALUES (?)", version); err != nil {
			return fmt.Errorf("record migration %d: %w", version, err)
		}
	}
	return nil
}
