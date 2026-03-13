// Command exportlogs extracts entries from the greyproxy SQLite database
// into individual JSON files organized by table, ready for analysis.
package main

import (
	"bytes"
	"compress/gzip"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	_ "modernc.org/sqlite"
)

func main() {
	dbPath := flag.String("db", "greyproxy.db", "path to greyproxy SQLite database")
	outDir := flag.String("out", "exported_logs", "output directory for JSON files")
	flag.Parse()

	db, err := sql.Open("sqlite", *dbPath)
	if err != nil {
		log.Fatalf("open db: %v", err)
	}
	defer db.Close()

	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		log.Fatalf("create output dir: %v", err)
	}

	tables := []string{"request_logs", "rules", "pending_requests"}
	for _, table := range tables {
		if err := exportTable(db, table, *outDir); err != nil {
			log.Printf("warning: %s: %v", table, err)
		}
	}

	// Also try http_transactions if it exists (MITM feature)
	if err := exportTable(db, "http_transactions", *outDir); err != nil {
		log.Printf("note: http_transactions not exported (may not exist): %v", err)
	}

	fmt.Printf("Done. Exported to %s/\n", *outDir)
}

// blobColumns lists columns that store binary data and need special handling.
var blobColumns = map[string]bool{
	"response_body": true,
	"request_body":  true,
}

// tryDecompressGzip attempts to decompress gzip data. Returns the decompressed
// bytes and true if successful, or the original bytes and false otherwise.
func tryDecompressGzip(data []byte) ([]byte, bool) {
	if len(data) < 2 || data[0] != 0x1f || data[1] != 0x8b {
		return data, false
	}
	r, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return data, false
	}
	defer r.Close()
	decompressed, err := io.ReadAll(r)
	if err != nil {
		return data, false
	}
	return decompressed, true
}

func exportTable(db *sql.DB, table string, outDir string) error {
	// Verify the table exists
	var name string
	err := db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name=?", table).Scan(&name)
	if err != nil {
		return fmt.Errorf("table %q not found", table)
	}

	rows, err := db.Query("SELECT * FROM " + table) //nolint: the table name comes from our hardcoded list
	if err != nil {
		return fmt.Errorf("query %s: %w", table, err)
	}
	defer rows.Close()

	cols, err := rows.Columns()
	if err != nil {
		return fmt.Errorf("columns %s: %w", table, err)
	}

	tableDir := filepath.Join(outDir, table)
	if err := os.MkdirAll(tableDir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", tableDir, err)
	}

	count := 0
	for rows.Next() {
		values := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range values {
			ptrs[i] = &values[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return fmt.Errorf("scan row: %w", err)
		}

		record := make(map[string]any, len(cols))
		for i, col := range cols {
			v := values[i]
			b, ok := v.([]byte)
			if !ok {
				record[col] = v
				continue
			}

			if blobColumns[col] {
				// For known BLOB columns: try gzip decompression first,
				// then check if the result is valid UTF-8 text.
				data := b
				wasCompressed := false
				decompressed, ok := tryDecompressGzip(data)
				if ok {
					data = decompressed
					wasCompressed = true
				}

				if utf8.Valid(data) {
					record[col] = string(data)
					if wasCompressed {
						record[col+"_was_compressed"] = true
					}
				} else {
					// Binary data that isn't valid UTF-8: base64 encode it
					record[col] = base64.StdEncoding.EncodeToString(data)
					record[col+"_encoding"] = "base64"
				}
			} else {
				// For TEXT columns returned as []byte by the sqlite driver
				record[col] = string(b)
			}
		}

		// For http_transactions, parse and clean up response_body if it was
		// an SSE stream (text/event-stream) - extract just the data events.
		if table == "http_transactions" {
			if ct, ok := record["response_content_type"].(string); ok && strings.Contains(ct, "text/event-stream") {
				if body, ok := record["response_body"].(string); ok && record["response_body_encoding"] != "base64" {
					record["response_body_events"] = parseSSEEvents(body)
				}
			}
		}

		id := fmt.Sprintf("%04d", count+1)
		if v, ok := record["id"]; ok {
			id = fmt.Sprintf("%v", v)
		}
		filename := filepath.Join(tableDir, fmt.Sprintf("%s.json", id))

		data, err := json.MarshalIndent(record, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal: %w", err)
		}
		if err := os.WriteFile(filename, data, 0o644); err != nil {
			return fmt.Errorf("write %s: %w", filename, err)
		}
		count++
	}

	fmt.Printf("  %s: %d entries\n", table, count)
	return nil
}

// parseSSEEvents extracts data payloads from a Server-Sent Events stream.
func parseSSEEvents(body string) []map[string]string {
	var events []map[string]string
	var currentEvent map[string]string

	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimRight(line, "\r")

		if line == "" {
			if currentEvent != nil {
				events = append(events, currentEvent)
				currentEvent = nil
			}
			continue
		}

		if strings.HasPrefix(line, "event: ") {
			if currentEvent == nil {
				currentEvent = make(map[string]string)
			}
			currentEvent["event"] = strings.TrimPrefix(line, "event: ")
		} else if strings.HasPrefix(line, "data: ") {
			if currentEvent == nil {
				currentEvent = make(map[string]string)
			}
			currentEvent["data"] = strings.TrimPrefix(line, "data: ")
		}
	}

	if currentEvent != nil {
		events = append(events, currentEvent)
	}

	return events
}
