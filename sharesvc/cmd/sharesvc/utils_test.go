package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSafeJoinAndCheck(t *testing.T) {
	// Create a temporary directory for testing
	tmpDir, err := os.MkdirTemp("", "warp-share-test")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// Create a subdirectory "media" to act as root
	mediaRoot := filepath.Join(tmpDir, "media")
	if err := os.Mkdir(mediaRoot, 0755); err != nil {
		t.Fatal(err)
	}

	// Create a symlink that points outside
	outsideDir := filepath.Join(tmpDir, "outside")
	if err := os.Mkdir(outsideDir, 0755); err != nil {
		t.Fatal(err)
	}
	symlinkBad := filepath.Join(mediaRoot, "symlink_bad")
	if err := os.Symlink(outsideDir, symlinkBad); err != nil {
		t.Fatal(err)
	}

	// Create a valid file inside
	validFile := filepath.Join(mediaRoot, "valid.txt")
	if err := os.WriteFile(validFile, []byte("ok"), 0644); err != nil {
		t.Fatal(err)
	}

	// Create a valid subdir
	subDir := filepath.Join(mediaRoot, "sub")
	if err := os.Mkdir(subDir, 0755); err != nil {
		t.Fatal(err)
	}

	// Symlink inside that is valid
	symlinkGood := filepath.Join(mediaRoot, "symlink_good")
	if err := os.Symlink(subDir, symlinkGood); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name      string
		root      string
		rel       string
		wantErr   bool
		checkPath string // if empty, just check for no error
	}{
		{
			name:    "Simple valid file",
			root:    mediaRoot,
			rel:     "valid.txt",
			wantErr: false,
		},
		{
			name:    "Dot",
			root:    mediaRoot,
			rel:     ".",
			wantErr: false,
		},
		{
			name:    "Empty",
			root:    mediaRoot,
			rel:     "",
			wantErr: false,
		},
		{
			name:    "Parent traversal ..",
			root:    mediaRoot,
			rel:     "../outside",
			wantErr: true,
		},
		{
			name:    "Root traversal /",
			root:    mediaRoot,
			rel:     "/etc/passwd",
			wantErr: true,
		},
		{
			name:    "Symlink pointing outside",
			root:    mediaRoot,
			rel:     "symlink_bad/file.txt",
			wantErr: true,
		},
		{
			name:    "Symlink pointing inside",
			root:    mediaRoot,
			rel:     "symlink_good",
			wantErr: false,
		},
		{
			name:    "Windows backslash check",
			root:    mediaRoot,
			rel:     "sub\\file",
			wantErr: true, // we aggressively block backslashes
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := safeJoinAndCheck(tt.root, tt.rel)
			if (err != nil) != tt.wantErr {
				t.Errorf("safeJoinAndCheck() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && err == nil {
				// Verify it's actually inside
				// On Mac/Linux tmp might be symlinked, so we evalSymlinks heavily in the function
				// Here we just verify it exists
				if _, err := os.Stat(got); err != nil {
					t.Fatalf("expected path to exist: %v", err)
				}
			}
		})
	}
}

// ============================================================================
// sha256Hex Tests
// ============================================================================

func TestSha256Hex(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
		{"hello", "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"},
		{"test123", "ecd71870d1963316a97e3ac3408c9835ad8cf0f3c1bc703527c30265534f75ae"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := sha256Hex(tt.input)
			if got != tt.expected {
				t.Errorf("sha256Hex(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

// ============================================================================
// looksLikeToken Tests
// ============================================================================

func TestLooksLikeToken(t *testing.T) {
	tests := []struct {
		name   string
		s      string
		minLen int
		want   bool
	}{
		{"valid alphanumeric", "abc123XYZ", 5, true},
		{"valid with dash", "abc-123", 5, true},
		{"valid with underscore", "abc_123", 5, true},
		{"too short", "abc", 5, false},
		{"too long", strings.Repeat("a", 129), 5, false},
		{"max length ok", strings.Repeat("a", 128), 5, true},
		{"empty string", "", 1, false},
		{"contains space", "abc 123", 5, false},
		{"contains dot", "abc.123", 5, false},
		{"contains slash", "abc/123", 5, false},
		{"contains special char", "abc@123", 5, false},
		{"exactly min length", "abcde", 5, true},
		{"one less than min", "abcd", 5, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := looksLikeToken(tt.s, tt.minLen); got != tt.want {
				t.Errorf("looksLikeToken(%q, %d) = %v, want %v", tt.s, tt.minLen, got, tt.want)
			}
		})
	}
}

// ============================================================================
// randomToken Tests
// ============================================================================

func TestRandomToken(t *testing.T) {
	t.Run("generates correct length", func(t *testing.T) {
		token, err := randomToken(32)
		if err != nil {
			t.Fatalf("randomToken(32) error = %v", err)
		}
		// 32 bytes -> 43 base64 chars (without padding)
		if len(token) != 43 {
			t.Errorf("randomToken(32) length = %d, want 43", len(token))
		}
	})

	t.Run("generates unique tokens", func(t *testing.T) {
		tokens := make(map[string]bool)
		for i := 0; i < 100; i++ {
			token, err := randomToken(16)
			if err != nil {
				t.Fatalf("randomToken(16) error = %v", err)
			}
			if tokens[token] {
				t.Errorf("randomToken generated duplicate: %s", token)
			}
			tokens[token] = true
		}
	})

	t.Run("zero bytes", func(t *testing.T) {
		token, err := randomToken(0)
		if err != nil {
			t.Fatalf("randomToken(0) error = %v", err)
		}
		if token != "" {
			t.Errorf("randomToken(0) = %q, want empty", token)
		}
	})
}

func TestRandomTokenError(t *testing.T) {
	old := randRead
	randRead = func(b []byte) (int, error) { return 0, errors.New("boom") }
	defer func() { randRead = old }()

	if _, err := randomToken(1); err == nil {
		t.Error("expected error from randomToken when randRead fails")
	}
}

// ============================================================================
// formatRemaining Tests
// ============================================================================

func TestFormatRemaining(t *testing.T) {
	tests := []struct {
		name          string
		maxDownloads  int64
		usedDownloads int64
		want          string
	}{
		{"unlimited", 0, 0, "∞"},
		{"unlimited with used", 0, 100, "∞"},
		{"10 remaining", 10, 0, "10"},
		{"5 remaining", 10, 5, "5"},
		{"0 remaining", 10, 10, "0"},
		{"negative clamp", 10, 15, "0"},
		{"large numbers", 1000000, 999999, "1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := formatRemaining(tt.maxDownloads, tt.usedDownloads); got != tt.want {
				t.Errorf("formatRemaining(%d, %d) = %q, want %q", tt.maxDownloads, tt.usedDownloads, got, tt.want)
			}
		})
	}
}

// ============================================================================
// getClientIP Tests
// ============================================================================

func TestGetClientIP(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		xRealIP    string
		want       string
	}{
		{"from RemoteAddr", "192.168.1.1:12345", "", "192.168.1.1"},
		{"from X-Real-IP", "10.0.0.1:12345", "203.0.113.50", "203.0.113.50"},
		{"X-Real-IP takes precedence", "10.0.0.1:12345", "8.8.8.8", "8.8.8.8"},
		{"invalid X-Real-IP ignored", "192.168.1.1:12345", "not-an-ip", "192.168.1.1"},
		{"IPv6 RemoteAddr", "[::1]:12345", "", "::1"},
		{"IPv6 X-Real-IP", "[::1]:12345", "2001:db8::1", "2001:db8::1"},
		{"RemoteAddr without port", "192.168.1.1", "", "192.168.1.1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.RemoteAddr = tt.remoteAddr
			if tt.xRealIP != "" {
				r.Header.Set("X-Real-IP", tt.xRealIP)
			}
			if got := getClientIP(r); got != tt.want {
				t.Errorf("getClientIP() = %q, want %q", got, tt.want)
			}
		})
	}
}

// ============================================================================
// nowRFC3339 Tests
// ============================================================================

func TestNowRFC3339(t *testing.T) {
	before := time.Now().UTC()
	result := nowRFC3339()
	after := time.Now().UTC()

	parsed, err := time.Parse(time.RFC3339, result)
	if err != nil {
		t.Fatalf("nowRFC3339() returned invalid RFC3339: %v", err)
	}

	if parsed.Before(before.Add(-time.Second)) || parsed.After(after.Add(time.Second)) {
		t.Errorf("nowRFC3339() = %s, not within expected range", result)
	}
}

// ============================================================================
// jsonError Tests
// ============================================================================

func TestJSONError(t *testing.T) {
	rr := httptest.NewRecorder()
	jsonError(rr, http.StatusBadRequest, "invalid", "Something went wrong")

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/json; charset=utf-8" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "\"error\":\"invalid\"") || !strings.Contains(body, "\"message\":\"Something went wrong\"") {
		t.Errorf("body = %q, want error/message JSON", body)
	}
}

// ============================================================================
// flushResponseWriter Tests
// ============================================================================

type flushRecorder struct {
	*httptest.ResponseRecorder
	flushed bool
}

func (f *flushRecorder) Flush() {
	f.flushed = true
}

func TestFlushResponseWriter(t *testing.T) {
	fr := &flushRecorder{ResponseRecorder: httptest.NewRecorder()}
	flushResponseWriter(fr)
	if !fr.flushed {
		t.Error("flushResponseWriter should call Flush when supported")
	}

	rr := httptest.NewRecorder()
	flushResponseWriter(rr)
}
