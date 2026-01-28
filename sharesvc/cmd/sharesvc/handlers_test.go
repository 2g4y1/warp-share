package main

import (
	"context"
	"database/sql"
	"html/template"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	_ "modernc.org/sqlite"
)

// Helper to create test app with in-memory DB
func newTestApp(t *testing.T) *app {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	repo := NewRepository(db)
	if err := repo.InitDB(); err != nil {
		t.Fatal(err)
	}

	dataDir := t.TempDir()
	mediaRoot := t.TempDir()

	// Initialize CSRF secret
	csrfSecret = []byte("test-secret-key-32-bytes-long!!!")

	// Load templates from embedded content
	tmplLogin := template.Must(template.ParseFS(content, "assets/login.html"))
	tmplAdmin := template.Must(template.New("admin.html").Funcs(template.FuncMap{
		"eq":   func(a, b string) bool { return a == b },
		"base": filepath.Base,
		"truncate": func(l int, s string) string {
			if l <= 0 {
				return ""
			}
			runeCount := utf8.RuneCountInString(s)
			if runeCount <= l {
				return s
			}
			if l == 1 {
				return "…"
			}
			runes := []rune(s)
			return string(runes[:l-1]) + "…"
		},
		"timeRel": func(s string) string {
			if s == "-" || s == "unlimited" {
				return s
			}
			return s
		},
	}).ParseFS(content, "assets/admin.html"))
	tmplBrowse := template.Must(template.ParseFS(content, "assets/browse.html"))
	tmplLanding := template.Must(template.ParseFS(content, "assets/landing.html"))

	return &app{
		repo: repo,
		cfg: config{
			AdminPath:   "/test-admin",
			PublicBase:  "https://test.example.com",
			DataDir:     dataDir,
			MediaRoot:   mediaRoot,
			DBTimeout:   2 * time.Second,
			GrantTTL:    time.Hour,
			SessionTTL:  time.Hour,
			BrowseStartRel: "media",
		},
		sl:          NewSpeedLimiter(),
		tmplLogin:   tmplLogin,
		tmplAdmin:   tmplAdmin,
		tmplBrowse:  tmplBrowse,
		tmplLanding: tmplLanding,
	}
}

// ============================================================================
// Health Check Handler Tests
// ============================================================================

func TestHandleHealth(t *testing.T) {
	a := newTestApp(t)

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rr := httptest.NewRecorder()

	a.handleHealth(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	if got := strings.TrimSpace(rr.Body.String()); got != "ok" {
		t.Errorf("body = %q, want %q", got, "ok")
	}
}

// ============================================================================
// Static Asset Handler Tests
// ============================================================================

func TestHandlePublicAppJS(t *testing.T) {
	a := newTestApp(t)

	req := httptest.NewRequest(http.MethodGet, "/warp-share.js", nil)
	rr := httptest.NewRecorder()

	a.handlePublicAppJS(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	if ct := rr.Header().Get("Content-Type"); !strings.Contains(ct, "javascript") {
		t.Errorf("Content-Type = %q, want JavaScript", ct)
	}
}

func TestHandlePublicCSS(t *testing.T) {
	a := newTestApp(t)

	req := httptest.NewRequest(http.MethodGet, "/warp-share.css", nil)
	rr := httptest.NewRecorder()

	a.handlePublicCSS(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "text/css; charset=utf-8" {
		t.Errorf("Content-Type = %q, want CSS", ct)
	}
}

func TestHandleAdminStaticAppJS(t *testing.T) {
	a := newTestApp(t)

	req := httptest.NewRequest(http.MethodGet, "/test-admin/static/app.js", nil)
	rr := httptest.NewRecorder()

	a.handleAdminStaticAppJS(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}
}

// ============================================================================
// Admin Auth Handler Tests
// ============================================================================

func TestHandleAdminLoginForm(t *testing.T) {
	a := newTestApp(t)

	req := httptest.NewRequest(http.MethodGet, "/test-admin/login", nil)
	rr := httptest.NewRecorder()

	a.handleAdminLoginForm(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	if !strings.Contains(rr.Body.String(), "form") {
		t.Error("response should contain login form")
	}
}

func TestRequireAdmin(t *testing.T) {
	t.Run("redirects without session", func(t *testing.T) {
		a := newTestApp(t)
		called := false
		handler := a.requireAdmin(func(w http.ResponseWriter, r *http.Request) {
			called = true
			w.WriteHeader(http.StatusOK)
		})

		req := httptest.NewRequest(http.MethodGet, "/test-admin/", nil)
		rr := httptest.NewRecorder()

		handler(rr, req)

		if called {
			t.Error("handler should not be called without auth")
		}
		if rr.Code != http.StatusSeeOther {
			t.Errorf("status = %d, want redirect %d", rr.Code, http.StatusSeeOther)
		}
	})

	t.Run("allows with valid session", func(t *testing.T) {
		a := newTestApp(t)
		called := false
		handler := a.requireAdmin(func(w http.ResponseWriter, r *http.Request) {
			called = true
			w.WriteHeader(http.StatusOK)
		})

		// Insert user directly to avoid bcrypt cost
		_, err := a.repo.db.Exec(`
			INSERT INTO users (id, username, password_hash, created_at)
			VALUES (1, 'admin', 'hash', ?)
		`, nowRFC3339())
		if err != nil {
			t.Fatal(err)
		}

		// Create session directly
		sessionToken, _ := randomToken(32)
		ctx := context.Background()
		if err := a.repo.CreateSession(ctx, 1, sha256Hex(sessionToken), time.Hour); err != nil {
			t.Fatal(err)
		}

		req := httptest.NewRequest(http.MethodGet, "/test-admin/", nil)
		req.AddCookie(&http.Cookie{Name: "warp_admin", Value: sessionToken})
		rr := httptest.NewRecorder()

		handler(rr, req)

		if !called {
			t.Error("handler should be called with valid session")
		}
	})
}

// ============================================================================
// Root Handler Tests
// ============================================================================

func TestHandleRoot(t *testing.T) {
	a := newTestApp(t)

	t.Run("returns 404 for empty path", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rr := httptest.NewRecorder()

		a.handleRoot(rr, req)

		if rr.Code != http.StatusNotFound {
			t.Errorf("status = %d, want %d", rr.Code, http.StatusNotFound)
		}
	})

	t.Run("returns 404 for single segment", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/something", nil)
		rr := httptest.NewRecorder()

		a.handleRoot(rr, req)

		if rr.Code != http.StatusNotFound {
			t.Errorf("status = %d, want %d", rr.Code, http.StatusNotFound)
		}
	})

	t.Run("returns 404 for invalid token format", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/abc/def", nil)
		rr := httptest.NewRecorder()

		a.handleRoot(rr, req)

		if rr.Code != http.StatusNotFound {
			t.Errorf("status = %d, want %d", rr.Code, http.StatusNotFound)
		}
	})

	t.Run("returns 404 for nonexistent link", func(t *testing.T) {
		// Valid format but doesn't exist
		req := httptest.NewRequest(http.MethodGet, "/abcdef123456/abcdefghij12345678901234", nil)
		rr := httptest.NewRecorder()

		a.handleRoot(rr, req)

		if rr.Code != http.StatusNotFound {
			t.Errorf("status = %d, want %d", rr.Code, http.StatusNotFound)
		}
	})
}

// ============================================================================
// Utility Functions in Handlers Tests
// ============================================================================

func TestGetBaseURL(t *testing.T) {
	tests := []struct {
		name           string
		remoteAddr     string
		host           string
		xForwardedProto string
		xForwardedHost string
		fallback       string
		want           string
	}{
		{
			name:       "uses fallback when no headers",
			remoteAddr: "8.8.8.8:1234",
			host:       "",
			fallback:   "https://example.com",
			want:       "https://example.com",
		},
		{
			name:           "uses X-Forwarded headers from trusted source",
			remoteAddr:     "127.0.0.1:1234",
			host:           "internal.host",
			xForwardedProto: "https",
			xForwardedHost: "public.example.com",
			fallback:       "https://fallback.com",
			want:           "https://public.example.com",
		},
		{
			name:       "uses Host header when not trusted",
			remoteAddr: "8.8.8.8:1234",
			host:       "direct.host:8080",
			fallback:   "https://fallback.com",
			want:       "http://direct.host:8080",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = tt.remoteAddr
			req.Host = tt.host
			if tt.xForwardedProto != "" {
				req.Header.Set("X-Forwarded-Proto", tt.xForwardedProto)
			}
			if tt.xForwardedHost != "" {
				req.Header.Set("X-Forwarded-Host", tt.xForwardedHost)
			}

			got := getBaseURL(req, tt.fallback)
			if got != tt.want {
				t.Errorf("getBaseURL() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseInt64Default(t *testing.T) {
	tests := []struct {
		s    string
		def  int64
		want int64
	}{
		{"123", 0, 123},
		{"", 42, 42},
		{"invalid", 42, 42},
		{"-5", 0, -5},
		{"0", 10, 0},
	}

	for _, tt := range tests {
		got := parseInt64Default(tt.s, tt.def)
		if got != tt.want {
			t.Errorf("parseInt64Default(%q, %d) = %d, want %d", tt.s, tt.def, got, tt.want)
		}
	}
}

func TestParseOptionalInt64(t *testing.T) {
	tests := []struct {
		s       string
		wantNil bool
		want    int64
	}{
		{"", true, 0},
		{"123", false, 123},
		{"0", false, 0},
		{"-1", false, -1},
	}

	for _, tt := range tests {
		got := parseOptionalInt64(tt.s)
		if tt.wantNil {
			if got != nil {
				t.Errorf("parseOptionalInt64(%q) = %v, want nil", tt.s, *got)
			}
		} else {
			if got == nil {
				t.Errorf("parseOptionalInt64(%q) = nil, want %d", tt.s, tt.want)
			} else if *got != tt.want {
				t.Errorf("parseOptionalInt64(%q) = %d, want %d", tt.s, *got, tt.want)
			}
		}
	}
}

func TestSanitizeFilename(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"normal.txt", "normal.txt"},
		{"../../../etc/passwd", "_.._.._etc_passwd"},
		{"file with spaces.txt", "file with spaces.txt"},
		{"file/with/slashes.txt", "file_with_slashes.txt"},
		{"file\\with\\backslashes.txt", "file_with_backslashes.txt"},
		{"bad\x00name.txt", "badname.txt"},
		{"", ""},
		{".hidden", "hidden"},
		{"..dangerous", "dangerous"},
	}

	for _, tt := range tests {
		got := sanitizeFilename(tt.input)
		if got != tt.want {
			t.Errorf("sanitizeFilename(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}

	// Long filename truncation
	longExt := strings.Repeat("e", 60)
	longBase := strings.Repeat("b", 260)
	name := longBase + "." + longExt
	got := sanitizeFilename(name)
	if len(got) > 255 {
		t.Errorf("sanitizeFilename length = %d, want <= 255", len(got))
	}
}

func TestParseUserTime(t *testing.T) {
	tests := []struct {
		input   string
		wantOK  bool
	}{
		{"2025-01-15T10:30", true},
		{"2025-12-31T23:59", true},
		{"invalid", false},
		{"", false},
		{"2025-01-15", false}, // missing time
	}

	for _, tt := range tests {
		_, ok := parseUserTime(tt.input)
		if ok != tt.wantOK {
			t.Errorf("parseUserTime(%q) ok = %v, want %v", tt.input, ok, tt.wantOK)
		}
	}
}
