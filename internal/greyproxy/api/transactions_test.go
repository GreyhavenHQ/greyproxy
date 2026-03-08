package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gin-gonic/gin"
	greyproxy "github.com/greyhavenhq/greyproxy/internal/greyproxy"
	_ "modernc.org/sqlite"
)

func setupTestShared(t *testing.T) *Shared {
	t.Helper()

	tmpFile, err := os.CreateTemp("", "greyproxy_api_test_*.db")
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

	return &Shared{
		DB:  db,
		Bus: greyproxy.NewEventBus(),
	}
}

func seedTransactions(t *testing.T, s *Shared) {
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
			ResponseHeaders:     http.Header{"Content-Type": {"application/json"}},
			ResponseBody:        []byte(`{"users":[]}`),
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
			ResponseHeaders:     http.Header{"Content-Type": {"application/json"}},
			ResponseBody:        []byte(`{"id":1,"name":"alice"}`),
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
		if _, err := greyproxy.CreateHttpTransaction(s.DB, input); err != nil {
			t.Fatal(err)
		}
	}
}

func TestTransactionsListAPI(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := setupTestShared(t)
	seedTransactions(t, s)

	r := gin.New()
	r.GET("/api/transactions", TransactionsListHandler(s))

	t.Run("returns all transactions", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/api/transactions", nil)
		r.ServeHTTP(w, req)

		if w.Code != 200 {
			t.Fatalf("status: got %d, want 200", w.Code)
		}

		var resp struct {
			Items []greyproxy.HttpTransactionJSON `json:"items"`
			Total int                             `json:"total"`
			Page  int                             `json:"page"`
			Pages int                             `json:"pages"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		if resp.Total != 3 {
			t.Errorf("total: got %d, want 3", resp.Total)
		}
		if len(resp.Items) != 3 {
			t.Fatalf("items: got %d, want 3", len(resp.Items))
		}
		// Most recent first
		if resp.Items[0].Method != "PUT" {
			t.Errorf("first item method: got %q, want PUT", resp.Items[0].Method)
		}
		// List view should NOT include bodies
		if resp.Items[0].RequestBody != nil {
			t.Error("list view should not include request_body")
		}
		if resp.Items[0].ResponseBody != nil {
			t.Error("list view should not include response_body")
		}
	})

	t.Run("filter by method", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/api/transactions?method=GET", nil)
		r.ServeHTTP(w, req)

		var resp struct {
			Items []greyproxy.HttpTransactionJSON `json:"items"`
			Total int                             `json:"total"`
		}
		json.Unmarshal(w.Body.Bytes(), &resp)
		if resp.Total != 1 {
			t.Errorf("total: got %d, want 1", resp.Total)
		}
		if len(resp.Items) != 1 || resp.Items[0].Method != "GET" {
			t.Error("expected single GET transaction")
		}
	})

	t.Run("filter by container", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/api/transactions?container=worker", nil)
		r.ServeHTTP(w, req)

		var resp struct {
			Items []greyproxy.HttpTransactionJSON `json:"items"`
			Total int                             `json:"total"`
		}
		json.Unmarshal(w.Body.Bytes(), &resp)
		if resp.Total != 1 {
			t.Errorf("total: got %d, want 1", resp.Total)
		}
	})

	t.Run("filter by destination", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/api/transactions?destination=storage", nil)
		r.ServeHTTP(w, req)

		var resp struct {
			Items []greyproxy.HttpTransactionJSON `json:"items"`
			Total int                             `json:"total"`
		}
		json.Unmarshal(w.Body.Bytes(), &resp)
		if resp.Total != 1 {
			t.Errorf("total: got %d, want 1", resp.Total)
		}
	})

	t.Run("pagination", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/api/transactions?limit=2", nil)
		r.ServeHTTP(w, req)

		var resp struct {
			Items []greyproxy.HttpTransactionJSON `json:"items"`
			Total int                             `json:"total"`
			Page  int                             `json:"page"`
			Pages int                             `json:"pages"`
		}
		json.Unmarshal(w.Body.Bytes(), &resp)
		if len(resp.Items) != 2 {
			t.Errorf("items: got %d, want 2", len(resp.Items))
		}
		if resp.Total != 3 {
			t.Errorf("total: got %d, want 3", resp.Total)
		}
		if resp.Pages != 2 {
			t.Errorf("pages: got %d, want 2", resp.Pages)
		}
	})

	t.Run("empty result", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/api/transactions?method=DELETE", nil)
		r.ServeHTTP(w, req)

		var resp struct {
			Items []greyproxy.HttpTransactionJSON `json:"items"`
			Total int                             `json:"total"`
		}
		json.Unmarshal(w.Body.Bytes(), &resp)
		if resp.Total != 0 {
			t.Errorf("total: got %d, want 0", resp.Total)
		}
		if len(resp.Items) != 0 {
			t.Errorf("items: got %d, want 0", len(resp.Items))
		}
	})
}

func TestTransactionsDetailAPI(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := setupTestShared(t)
	seedTransactions(t, s)

	r := gin.New()
	r.GET("/api/transactions/:id", TransactionsDetailHandler(s))

	t.Run("returns full transaction with body", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/api/transactions/2", nil)
		r.ServeHTTP(w, req)

		if w.Code != 200 {
			t.Fatalf("status: got %d, want 200", w.Code)
		}

		var txn greyproxy.HttpTransactionJSON
		if err := json.Unmarshal(w.Body.Bytes(), &txn); err != nil {
			t.Fatal(err)
		}
		if txn.Method != "POST" {
			t.Errorf("method: got %q, want POST", txn.Method)
		}
		if txn.RequestBody == nil || *txn.RequestBody != `{"name":"alice"}` {
			t.Errorf("request_body missing or wrong: %v", txn.RequestBody)
		}
		if txn.ResponseBody == nil || *txn.ResponseBody != `{"id":1,"name":"alice"}` {
			t.Errorf("response_body missing or wrong: %v", txn.ResponseBody)
		}
		if txn.StatusCode == nil || *txn.StatusCode != 201 {
			t.Errorf("status_code: got %v, want 201", txn.StatusCode)
		}
	})

	t.Run("not found", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/api/transactions/999", nil)
		r.ServeHTTP(w, req)

		if w.Code != 404 {
			t.Errorf("status: got %d, want 404", w.Code)
		}
	})

	t.Run("invalid id", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/api/transactions/abc", nil)
		r.ServeHTTP(w, req)

		if w.Code != 400 {
			t.Errorf("status: got %d, want 400", w.Code)
		}
	})
}
