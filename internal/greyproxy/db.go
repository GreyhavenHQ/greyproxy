package greyproxy

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"time"
)

// DB wraps a SQLite database with a write mutex for safe concurrent access.
type DB struct {
	read  *sql.DB
	write *sql.DB
	mu    sync.Mutex // serializes all writes
}

// OpenDB opens a SQLite database with WAL mode and returns a DB wrapper.
func OpenDB(path string) (*DB, error) {
	dsn := fmt.Sprintf("%s?_journal_mode=WAL&_busy_timeout=5000&_synchronous=NORMAL&_foreign_keys=ON", path)

	writeDB, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open write db: %w", err)
	}
	writeDB.SetMaxOpenConns(1)

	readDB, err := sql.Open("sqlite", dsn)
	if err != nil {
		_ = writeDB.Close()
		return nil, fmt.Errorf("open read db: %w", err)
	}
	readDB.SetMaxOpenConns(4)

	// Enable WAL mode
	if _, err := writeDB.Exec("PRAGMA journal_mode=WAL"); err != nil {
		_ = writeDB.Close()
		_ = readDB.Close()
		return nil, fmt.Errorf("enable WAL: %w", err)
	}

	return &DB{read: readDB, write: writeDB}, nil
}

// ReadDB returns the read-only database connection pool.
func (db *DB) ReadDB() *sql.DB {
	return db.read
}

// WriteDB returns the write database connection (single writer).
// Callers must hold the write lock via Lock()/Unlock().
func (db *DB) WriteDB() *sql.DB {
	return db.write
}

// Lock acquires the write mutex.
func (db *DB) Lock() {
	db.mu.Lock()
}

// Unlock releases the write mutex.
func (db *DB) Unlock() {
	db.mu.Unlock()
}

// Ping checks whether the database is reachable.
func (db *DB) Ping() error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return db.read.PingContext(ctx)
}

// Close closes both database connections.
func (db *DB) Close() error {
	err1 := db.read.Close()
	err2 := db.write.Close()
	if err1 != nil {
		return err1
	}
	return err2
}

// Migrate runs all database migrations.
func (db *DB) Migrate() error {
	db.mu.Lock()
	defer db.mu.Unlock()
	return runMigrations(db.write)
}
