package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	greyproxy "github.com/greyhavenhq/greyproxy/internal/greyproxy"
)

func newMiddlewareTestRouter(s *Shared) *gin.Engine {
	r := gin.New()
	r.GET("/api/middlewares", MiddlewaresListHandler(s))
	return r
}

func TestMiddlewaresListHandler_noFn_returnsEmptyArray(t *testing.T) {
	// When middlewares are not configured at all (the common case),
	// MiddlewareStatusesFn stays nil. The handler must still return an
	// empty array so the UI can render "no middlewares configured"
	// instead of hitting an error.
	s := &Shared{}
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/middlewares", nil)
	newMiddlewareTestRouter(s).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var got struct {
		Middlewares []greyproxy.MiddlewareStatus `json:"middlewares"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Middlewares == nil {
		t.Fatal("middlewares field is nil; want non-nil empty array")
	}
	if len(got.Middlewares) != 0 {
		t.Fatalf("len = %d, want 0", len(got.Middlewares))
	}
}

func TestMiddlewaresListHandler_returnsLiveSnapshot(t *testing.T) {
	// Each call to the handler invokes MiddlewareStatusesFn, so flips in
	// Connected between calls are visible without a restart or an event.
	calls := 0
	s := &Shared{
		MiddlewareStatusesFn: func() []greyproxy.MiddlewareStatus {
			calls++
			return []greyproxy.MiddlewareStatus{
				{
					URL:             "ws://localhost:9000/mw",
					Name:            "pii-redactor",
					Connected:       calls%2 == 1,
					ProtocolVersion: 1,
					Hooks:           []string{"http-request", "http-response"},
					MaxBodyBytes:    1 << 20,
					TimeoutMs:       10000,
					OnDisconnect:    "deny",
				},
			}
		},
	}

	for i := 0; i < 2; i++ {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/middlewares", nil)
		newMiddlewareTestRouter(s).ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("iter %d: status = %d", i, w.Code)
		}
		var got struct {
			Middlewares []greyproxy.MiddlewareStatus `json:"middlewares"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatalf("iter %d: decode: %v", i, err)
		}
		if len(got.Middlewares) != 1 {
			t.Fatalf("iter %d: len = %d, want 1", i, len(got.Middlewares))
		}
		mw := got.Middlewares[0]
		if mw.Name != "pii-redactor" {
			t.Errorf("name = %q", mw.Name)
		}
		wantConnected := (i%2 == 0) // calls is 1,2,3... so call N=1 -> Connected true (i=0)
		if mw.Connected != wantConnected {
			t.Errorf("iter %d: connected = %v, want %v", i, mw.Connected, wantConnected)
		}
	}
	if calls != 2 {
		t.Errorf("handler invoked fn %d times, want 2 (live snapshot)", calls)
	}
}

func init() {
	gin.SetMode(gin.TestMode)
}
