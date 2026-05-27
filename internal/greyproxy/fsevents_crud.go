package greyproxy

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
)

// InsertFsEventsBatch persists a heartbeat's worth of fs events under a
// single transaction. Called from the heartbeat handler *after*
// FsEventStore.Ingest has classified and correlated the events, so the
// Severity/Tags/TransactionID fields on each event are already set.
//
// Events arrive in bursts of dozens-to-hundreds per heartbeat; wrapping
// the inserts in a single explicit transaction keeps fsync to one call
// per heartbeat instead of one per event. Failures are returned to the
// caller but the heartbeat itself must always succeed (losing events is
// recoverable; losing the heartbeat TTL refresh is not), so the caller
// logs and continues.
func InsertFsEventsBatch(dbConn *DB, sessionID string, events []FsEvent) error {
	if sessionID == "" || len(events) == 0 {
		return nil
	}
	tx, err := dbConn.WriteDB().Begin()
	if err != nil {
		return fmt.Errorf("begin fs_events tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	stmt, err := tx.Prepare(`INSERT INTO fs_events
		(ts, session_id, transaction_id, op, path, path2, pid, errno, exe, severity, tags)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("prepare fs_events insert: %w", err)
	}
	defer func() { _ = stmt.Close() }()

	for i := range events {
		e := &events[i]
		var txID sql.NullInt64
		if e.TransactionID > 0 {
			txID = sql.NullInt64{Int64: e.TransactionID, Valid: true}
		}
		var path2 sql.NullString
		if e.Path2 != "" {
			path2 = sql.NullString{String: e.Path2, Valid: true}
		}
		var pid sql.NullInt64
		if e.PID > 0 {
			pid = sql.NullInt64{Int64: int64(e.PID), Valid: true}
		}
		var errno sql.NullInt64
		if e.Errno != 0 {
			errno = sql.NullInt64{Int64: int64(e.Errno), Valid: true}
		}
		var exe sql.NullString
		if e.Exe != "" {
			exe = sql.NullString{String: e.Exe, Valid: true}
		}
		var sev sql.NullString
		if e.Severity != "" {
			sev = sql.NullString{String: e.Severity, Valid: true}
		}
		var tags sql.NullString
		if len(e.Tags) > 0 {
			if b, err := json.Marshal(e.Tags); err == nil {
				tags = sql.NullString{String: string(b), Valid: true}
			}
		}
		if _, err := stmt.Exec(e.Ts, sessionID, txID, e.Op, e.Path, path2, pid, errno, exe, sev, tags); err != nil {
			return fmt.Errorf("insert fs_event: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit fs_events tx: %w", err)
	}
	return nil
}

// QueryFsEventsByConversation returns every fs event linked to any
// http_transactions row whose conversation_id matches. The conversation
// view uses this so an operator reading the prompt/response thread can
// see the agent's filesystem activity inline with the API calls that
// drove it, without clicking through to the Activity page once per
// transaction.
func QueryFsEventsByConversation(dbConn *DB, conversationID string) ([]FsEvent, error) {
	if conversationID == "" {
		return []FsEvent{}, nil
	}
	rows, err := dbConn.ReadDB().Query(`SELECT fs.ts, fs.session_id, fs.transaction_id, fs.op, fs.path, fs.path2, fs.pid, fs.errno, fs.exe, fs.severity, fs.tags
		FROM fs_events fs
		INNER JOIN http_transactions t ON fs.transaction_id = t.id
		WHERE t.conversation_id = ?
		ORDER BY fs.ts ASC, fs.id ASC`, conversationID)
	if err != nil {
		return nil, fmt.Errorf("query fs_events by conversation: %w", err)
	}
	defer func() { _ = rows.Close() }()
	return scanFsEventRows(rows)
}

// scanFsEventRows is the shared row-iteration body for the two query
// functions above. Keeping it in one place means a future column
// addition only requires changing one Scan call.
func scanFsEventRows(rows *sql.Rows) ([]FsEvent, error) {
	out := make([]FsEvent, 0)
	for rows.Next() {
		var (
			e         FsEvent
			sessionID string
			txCol     sql.NullInt64
			path2     sql.NullString
			pid       sql.NullInt64
			errno     sql.NullInt64
			exe       sql.NullString
			sev       sql.NullString
			tags      sql.NullString
		)
		if err := rows.Scan(&e.Ts, &sessionID, &txCol, &e.Op, &e.Path, &path2, &pid, &errno, &exe, &sev, &tags); err != nil {
			return nil, fmt.Errorf("scan fs_event: %w", err)
		}
		if txCol.Valid {
			e.TransactionID = txCol.Int64
		}
		if path2.Valid {
			e.Path2 = path2.String
		}
		if pid.Valid {
			e.PID = int(pid.Int64)
		}
		if errno.Valid {
			e.Errno = int(errno.Int64)
		}
		if exe.Valid {
			e.Exe = exe.String
		}
		if sev.Valid {
			e.Severity = sev.String
		}
		if tags.Valid && tags.String != "" {
			if strings.HasPrefix(tags.String, "[") {
				_ = json.Unmarshal([]byte(tags.String), &e.Tags)
			} else {
				e.Tags = []string{tags.String}
			}
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate fs_events: %w", err)
	}
	return out, nil
}

// QueryFsEventsByTransaction returns every persisted fs event linked to
// the given http_transactions row, in chronological order. Returns an
// empty slice (never nil) when no events match, so JSON encoders
// produce [] instead of null.
func QueryFsEventsByTransaction(dbConn *DB, txID int64) ([]FsEvent, error) {
	if txID <= 0 {
		return []FsEvent{}, nil
	}
	rows, err := dbConn.ReadDB().Query(`SELECT ts, session_id, transaction_id, op, path, path2, pid, errno, exe, severity, tags
		FROM fs_events
		WHERE transaction_id = ?
		ORDER BY ts ASC, id ASC`, txID)
	if err != nil {
		return nil, fmt.Errorf("query fs_events by tx: %w", err)
	}
	defer func() { _ = rows.Close() }()
	return scanFsEventRows(rows)
}
