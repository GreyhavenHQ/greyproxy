package ui

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	greyproxy "github.com/greyhavenhq/greyproxy/internal/greyproxy"
	_ "modernc.org/sqlite"
)

func setupTestDB(t *testing.T) *greyproxy.DB {
	t.Helper()

	tmpFile, err := os.CreateTemp("", "greyproxy_ui_test_*.db")
	if err != nil {
		t.Fatal(err)
	}
	tmpFile.Close()
	t.Cleanup(func() { os.Remove(tmpFile.Name()) })

	db, err := greyproxy.OpenDB(tmpFile.Name())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	return db
}

func seedTransactions(t *testing.T, db *greyproxy.DB) {
	t.Helper()
	txns := []greyproxy.HttpTransactionCreateInput{
		{
			ContainerName:       "webapp",
			DestinationHost:     "api.example.com",
			DestinationPort:     443,
			Method:              "GET",
			URL:                 "https://api.example.com/users",
			RequestHeaders:      http.Header{"Accept": {"application/json"}},
			StatusCode:          200,
			ResponseContentType: "application/json",
			DurationMs:          42,
			Result:              "auto",
		},
		{
			ContainerName:       "webapp",
			DestinationHost:     "api.example.com",
			DestinationPort:     443,
			Method:              "POST",
			URL:                 "https://api.example.com/users",
			RequestHeaders:      http.Header{"Content-Type": {"application/json"}},
			RequestBody:         []byte(`{"name":"alice"}`),
			RequestContentType:  "application/json",
			StatusCode:          201,
			ResponseContentType: "application/json",
			DurationMs:          85,
			Result:              "auto",
		},
		{
			ContainerName:   "worker",
			DestinationHost: "storage.example.com",
			DestinationPort: 443,
			Method:          "PUT",
			URL:             "https://storage.example.com/files/report.pdf",
			StatusCode:      500,
			DurationMs:      300,
			Result:          "auto",
		},
	}
	for _, input := range txns {
		if _, err := greyproxy.CreateHttpTransaction(db, input); err != nil {
			t.Fatal(err)
		}
	}
}

func setupRouter(t *testing.T, db *greyproxy.DB) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	g := r.Group("")
	bus := greyproxy.NewEventBus()
	RegisterPageRoutes(g, db, bus)
	RegisterHTMXRoutes(g, db, bus, nil, nil)
	return r
}

func TestTrafficPageRedirect(t *testing.T) {
	db := setupTestDB(t)
	r := setupRouter(t, db)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/traffic", nil)
	r.ServeHTTP(w, req)

	if w.Code != 302 {
		t.Fatalf("status: got %d, want 302", w.Code)
	}
	loc := w.Header().Get("Location")
	if loc != "/activity?kind=http" {
		t.Fatalf("redirect: got %q, want /activity?kind=http", loc)
	}
}

func TestActivityPageRoute(t *testing.T) {
	db := setupTestDB(t)
	r := setupRouter(t, db)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/activity", nil)
	r.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("status: got %d, want 200", w.Code)
	}

	body := w.Body.String()
	if !strings.Contains(body, "Activity") {
		t.Error("page missing title 'Activity'")
	}
	if !strings.Contains(body, "activity-table") {
		t.Error("page missing activity-table container")
	}
	if !strings.Contains(body, "activity-filter-form") {
		t.Error("page missing activity filter form")
	}
	if !strings.Contains(body, `href="/activity"`) {
		t.Error("page missing activity nav link")
	}
}

func TestTrafficTableHTMXRoute(t *testing.T) {
	db := setupTestDB(t)
	seedTransactions(t, db)
	r := setupRouter(t, db)

	t.Run("renders all transactions", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/htmx/traffic-table", nil)
		r.ServeHTTP(w, req)

		if w.Code != 200 {
			t.Fatalf("status: got %d, want 200", w.Code)
		}

		body := w.Body.String()
		// Should render all 3 rows (each has toggleTxnDetails)
		count := strings.Count(body, "toggleTxnDetails")
		if count != 3 {
			t.Errorf("rendered rows: got %d, want 3", count)
		}
		// Should show all methods
		if !strings.Contains(body, ">GET</span>") {
			t.Error("missing GET method badge")
		}
		if !strings.Contains(body, ">POST</span>") {
			t.Error("missing POST method badge")
		}
		if !strings.Contains(body, ">PUT</span>") {
			t.Error("missing PUT method badge")
		}
		// Should show status codes
		if !strings.Contains(body, ">200</span>") {
			t.Error("missing 200 status code")
		}
		if !strings.Contains(body, ">201</span>") {
			t.Error("missing 201 status code")
		}
		if !strings.Contains(body, ">500</span>") {
			t.Error("missing 500 status code")
		}
		// Should show container names
		if !strings.Contains(body, "webapp") {
			t.Error("missing container name 'webapp'")
		}
		if !strings.Contains(body, "worker") {
			t.Error("missing container name 'worker'")
		}
		// Should show URLs
		if !strings.Contains(body, "api.example.com/users") {
			t.Error("missing URL")
		}
		// Should show transaction count
		if !strings.Contains(body, "Showing 3 of 3 transactions") {
			t.Error("missing or wrong transaction count text")
		}
		// Status code colors: 200 should be green, 500 should be red
		if !strings.Contains(body, "text-green-600\">200") {
			t.Error("200 status should have green color class")
		}
		if !strings.Contains(body, "text-red-600\">500") {
			t.Error("500 status should have red color class")
		}
	})

	t.Run("filter by method", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/htmx/traffic-table?method=POST", nil)
		r.ServeHTTP(w, req)

		body := w.Body.String()
		count := strings.Count(body, "toggleTxnDetails")
		if count != 1 {
			t.Errorf("rendered rows: got %d, want 1", count)
		}
		if !strings.Contains(body, ">POST</span>") {
			t.Error("missing POST method")
		}
		if !strings.Contains(body, "Showing 1 of 1 transactions") {
			t.Error("wrong count text")
		}
	})

	t.Run("filter by container", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/htmx/traffic-table?container=worker", nil)
		r.ServeHTTP(w, req)

		body := w.Body.String()
		count := strings.Count(body, "toggleTxnDetails")
		if count != 1 {
			t.Errorf("rendered rows: got %d, want 1", count)
		}
		if !strings.Contains(body, "worker") {
			t.Error("missing container name 'worker'")
		}
	})

	t.Run("filter by destination", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/htmx/traffic-table?destination=storage", nil)
		r.ServeHTTP(w, req)

		body := w.Body.String()
		count := strings.Count(body, "toggleTxnDetails")
		if count != 1 {
			t.Errorf("rendered rows: got %d, want 1", count)
		}
	})

	t.Run("pagination", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/htmx/traffic-table?limit=2", nil)
		r.ServeHTTP(w, req)

		body := w.Body.String()
		count := strings.Count(body, "toggleTxnDetails")
		if count != 2 {
			t.Errorf("rendered rows: got %d, want 2", count)
		}
		if !strings.Contains(body, "Showing 2 of 3 transactions") {
			t.Error("wrong count text for paginated view")
		}
		if !strings.Contains(body, "Page 1 of 2") {
			t.Error("missing pagination info")
		}
	})

	t.Run("page 2", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/htmx/traffic-table?limit=2&page=2", nil)
		r.ServeHTTP(w, req)

		body := w.Body.String()
		count := strings.Count(body, "toggleTxnDetails")
		if count != 1 {
			t.Errorf("rendered rows on page 2: got %d, want 1", count)
		}
	})

	t.Run("empty result shows message", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/htmx/traffic-table?method=DELETE", nil)
		r.ServeHTTP(w, req)

		body := w.Body.String()
		if !strings.Contains(body, "No transactions match your filters") {
			t.Error("missing empty state message for filtered view")
		}
	})

	t.Run("no data shows empty state", func(t *testing.T) {
		emptyDB := setupTestDB(t)
		emptyRouter := setupRouter(t, emptyDB)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/htmx/traffic-table", nil)
		emptyRouter.ServeHTTP(w, req)

		body := w.Body.String()
		if !strings.Contains(body, "No HTTP transactions") {
			t.Error("missing empty state message")
		}
	})

	t.Run("method badges use primary color", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/htmx/traffic-table", nil)
		r.ServeHTTP(w, req)

		body := w.Body.String()
		// All method badges should use the same primary/orange color
		if !strings.Contains(body, "bg-primary/10 text-primary\">GET") {
			t.Error("GET badge missing primary color classes")
		}
		if !strings.Contains(body, "bg-primary/10 text-primary\">POST") {
			t.Error("POST badge missing primary color classes")
		}
		if !strings.Contains(body, "bg-primary/10 text-primary\">PUT") {
			t.Error("PUT badge missing primary color classes")
		}
	})

	t.Run("expandable details section present", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/htmx/traffic-table", nil)
		r.ServeHTTP(w, req)

		body := w.Body.String()
		// Each transaction should have a hidden details row
		detailCount := strings.Count(body, "txn-details-")
		// 3 transactions × 2 occurrences each (id attr + onclick ref) = but details rows have id="txn-details-N"
		if detailCount < 3 {
			t.Errorf("detail rows: got %d, want at least 3", detailCount)
		}
		if !strings.Contains(body, "Destination:") {
			t.Error("missing destination info in detail section")
		}
	})
}
