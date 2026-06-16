package api

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// TokenPath returns the platform-specific path for the API token file.
func TokenPath() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(os.Getenv("ProgramData"), "TPT", "api.token")
	}
	return "/etc/tpt/api.token"
}

// EnsureToken reads the token file or creates a new random token if absent.
// Returns the plaintext token. Logs the path so operators know where to find it.
func EnsureToken() (string, error) {
	path := TokenPath()
	if data, err := os.ReadFile(path); err == nil {
		token := strings.TrimSpace(string(data))
		if token != "" {
			return token, nil
		}
	}

	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	token := hex.EncodeToString(b)

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", err
	}
	if err := os.WriteFile(path, []byte(token+"\n"), 0o600); err != nil {
		return "", err
	}
	log.Printf("API token written to %s", path)
	return token, nil
}

// BearerMiddleware returns an HTTP middleware that enforces Bearer token authentication.
// Requests without a valid token receive 401 Unauthorized.
func BearerMiddleware(token string) func(http.Handler) http.Handler {
	sum := sha256.Sum256([]byte(token))
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			auth := r.Header.Get("Authorization")
			bearer := strings.TrimPrefix(auth, "Bearer ")
			if bearer == auth {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			candidate := sha256.Sum256([]byte(bearer))
			if subtle.ConstantTimeCompare(sum[:], candidate[:]) != 1 {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// WrapMux applies the API middleware chain to a ServeMux: loopback CORS on the
// outside (so dashboard preflight requests are never blocked by auth) and Bearer
// token auth on the inside when required. Returns the handler to use as the HTTP
// server's root handler.
func WrapMux(mux *http.ServeMux, requireAuth bool, token string) http.Handler {
	var h http.Handler = mux
	if requireAuth && token != "" {
		h = BearerMiddleware(token)(h)
	}
	return LoopbackCORS(h)
}

// LoopbackCORS allows cross-origin requests from loopback origins. The dashboard
// is served by one daemon (e.g. Guard on :7731) but also calls the other daemon
// (Patrol on :7732), which is a different origin. Only 127.0.0.1/localhost/::1
// origins are reflected; everything else gets no CORS headers. Pre-flight
// OPTIONS requests are answered here, before any auth check.
func LoopbackCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if isLoopbackOrigin(origin) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
			w.Header().Add("Vary", "Origin")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func isLoopbackOrigin(origin string) bool {
	if origin == "" {
		return false
	}
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	switch u.Hostname() {
	case "127.0.0.1", "localhost", "::1":
		return true
	default:
		return false
	}
}
