package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

func TestLoopbackCORSReflectsLoopbackOrigin(t *testing.T) {
	h := LoopbackCORS(okHandler())

	req := httptest.NewRequest(http.MethodGet, "/status", nil)
	req.Header.Set("Origin", "http://127.0.0.1:7731")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "http://127.0.0.1:7731" {
		t.Errorf("Allow-Origin = %q, want loopback origin reflected", got)
	}
}

func TestLoopbackCORSIgnoresRemoteOrigin(t *testing.T) {
	h := LoopbackCORS(okHandler())

	req := httptest.NewRequest(http.MethodGet, "/status", nil)
	req.Header.Set("Origin", "https://evil.example.com")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("Allow-Origin = %q, want empty for non-loopback origin", got)
	}
}

func TestLoopbackCORSPreflightShortCircuitsBeforeAuth(t *testing.T) {
	// Auth would reject any unauthenticated request, but an OPTIONS pre-flight
	// must be answered by the CORS layer before auth runs.
	mux := http.NewServeMux()
	mux.Handle("GET /status", okHandler())
	handler := WrapMux(mux, true, "secret-token")

	req := httptest.NewRequest(http.MethodOptions, "/status", nil)
	req.Header.Set("Origin", "http://localhost:7732")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Errorf("OPTIONS pre-flight status = %d, want 204", rec.Code)
	}
}

func TestWrapMuxEnforcesAuthOnRealRequest(t *testing.T) {
	mux := http.NewServeMux()
	mux.Handle("GET /status", okHandler())
	handler := WrapMux(mux, true, "secret-token")

	// No token → 401.
	req := httptest.NewRequest(http.MethodGet, "/status", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("unauthenticated GET status = %d, want 401", rec.Code)
	}

	// Correct token → 200.
	req2 := httptest.NewRequest(http.MethodGet, "/status", nil)
	req2.Header.Set("Authorization", "Bearer secret-token")
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Errorf("authenticated GET status = %d, want 200", rec2.Code)
	}
}
