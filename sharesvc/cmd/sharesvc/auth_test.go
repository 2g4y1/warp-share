package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// ============================================================================
// Rate Limiting Tests
// ============================================================================

func TestCheckLoginRateLimit(t *testing.T) {
	// Clear state before test
	loginAttempts.Lock()
	loginAttempts.m = make(map[string]*loginAttempt)
	loginAttempts.Unlock()

	ip := "192.168.1.100"

	t.Run("first attempt allowed", func(t *testing.T) {
		allowed, _ := checkLoginRateLimit(ip)
		if !allowed {
			t.Error("first attempt should be allowed")
		}
	})

	t.Run("multiple failures cause lockout", func(t *testing.T) {
		ip := "192.168.1.101"

		// First 2 failures should still allow
		for i := 0; i < 2; i++ {
			allowed, _ := checkLoginRateLimit(ip)
			if !allowed {
				t.Errorf("attempt %d should be allowed", i+1)
			}
			recordLoginFailure(ip)
		}

		// 3rd failure triggers 15s lockout
		recordLoginFailure(ip)
		allowed, retryAfter := checkLoginRateLimit(ip)
		if allowed {
			t.Error("should be locked after 3 failures")
		}
		if retryAfter < 10*time.Second || retryAfter > 20*time.Second {
			t.Errorf("retryAfter = %v, expected ~15s", retryAfter)
		}
	})
}

func TestRecordLoginFailure(t *testing.T) {
	// Clear state
	loginAttempts.Lock()
	loginAttempts.m = make(map[string]*loginAttempt)
	loginAttempts.Unlock()

	ip := "192.168.1.102"

	// Record 5 failures
	for i := 0; i < 5; i++ {
		recordLoginFailure(ip)
	}

	loginAttempts.RLock()
	attempt := loginAttempts.m[ip]
	count := attempt.count
	locked := !attempt.lockedUntil.IsZero()
	loginAttempts.RUnlock()

	if count != 5 {
		t.Errorf("count = %d, want 5", count)
	}
	if !locked {
		t.Error("should be locked after 5 failures")
	}
}

func TestClearLoginFailures(t *testing.T) {
	// Clear state
	loginAttempts.Lock()
	loginAttempts.m = make(map[string]*loginAttempt)
	loginAttempts.Unlock()

	ip := "192.168.1.103"

	// Add some failures
	recordLoginFailure(ip)
	recordLoginFailure(ip)

	// Clear
	clearLoginFailures(ip)

	loginAttempts.RLock()
	_, exists := loginAttempts.m[ip]
	loginAttempts.RUnlock()

	if exists {
		t.Error("entry should be deleted after clear")
	}
}

// ============================================================================
// CSRF Token Tests
// ============================================================================

func TestGenerateCSRFToken(t *testing.T) {
	// Initialize CSRF secret for testing
	csrfSecret = []byte("test-secret-key-32-bytes-long!!!")

	session1 := "session-token-1"
	session2 := "session-token-2"

	token1 := generateCSRFToken(session1)
	token2 := generateCSRFToken(session2)
	token1Again := generateCSRFToken(session1)

	t.Run("same session produces same token", func(t *testing.T) {
		if token1 != token1Again {
			t.Errorf("tokens differ for same session: %q vs %q", token1, token1Again)
		}
	})

	t.Run("different sessions produce different tokens", func(t *testing.T) {
		if token1 == token2 {
			t.Error("tokens should differ for different sessions")
		}
	})

	t.Run("token is valid hex", func(t *testing.T) {
		if len(token1) != 32 { // SHA256 hex truncated to 32 chars
			t.Errorf("token length = %d, want 32", len(token1))
		}
	})
}

// ============================================================================
// initCSRF Tests
// ============================================================================

func TestInitCSRF(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "csrf-test")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// Clear existing secret
	csrfSecret = nil

	t.Run("generates new secret", func(t *testing.T) {
		initCSRF(tmpDir)
		if len(csrfSecret) != 32 {
			t.Errorf("csrfSecret length = %d, want 32", len(csrfSecret))
		}

		// Check file was created
		keyFile := filepath.Join(tmpDir, "csrf.key")
		data, err := os.ReadFile(keyFile)
		if err != nil {
			t.Fatalf("failed to read key file: %v", err)
		}
		if len(data) != 32 {
			t.Errorf("key file length = %d, want 32", len(data))
		}
	})

	t.Run("reuses existing secret", func(t *testing.T) {
		originalSecret := make([]byte, 32)
		copy(originalSecret, csrfSecret)

		// Re-initialize
		initCSRF(tmpDir)

		for i := range csrfSecret {
			if csrfSecret[i] != originalSecret[i] {
				t.Error("secret should be reused from file")
				break
			}
		}
	})
}

func TestInitCSRFPanicOnRandError(t *testing.T) {
	old := randRead
	randRead = func(b []byte) (int, error) { return 0, errors.New("boom") }
	defer func() { randRead = old }()

	tmpDir, err := os.MkdirTemp("", "csrf-test")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic when randRead fails")
		}
	}()

	// ensure no key exists so generation runs
	csrfSecret = nil
	initCSRF(tmpDir)
}

// ============================================================================
// CSRF Validation & Middleware Tests
// ============================================================================

func TestValidateCSRFToken(t *testing.T) {
	a := newTestApp(t)
	csrfSecret = []byte("test-secret-key-32-bytes-long!!!")

	sessionToken := "session-abc"
	expected := generateCSRFToken(sessionToken)

	form := url.Values{"_csrf": []string{expected}}
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "warp_admin", Value: sessionToken})

	if !a.validateCSRFToken(req) {
		t.Error("validateCSRFToken should accept valid form token")
	}

	// multipart: use header token only
	req2 := httptest.NewRequest(http.MethodPost, "/", nil)
	req2.Header.Set("Content-Type", "multipart/form-data; boundary=xyz")
	req2.Header.Set("X-CSRF-Token", expected)
	req2.AddCookie(&http.Cookie{Name: "warp_admin", Value: sessionToken})
	if !a.validateCSRFToken(req2) {
		t.Error("validateCSRFToken should accept valid header token for multipart")
	}

	// invalid token length
	req3 := httptest.NewRequest(http.MethodPost, "/", nil)
	req3.Header.Set("X-CSRF-Token", "short")
	req3.AddCookie(&http.Cookie{Name: "warp_admin", Value: sessionToken})
	if a.validateCSRFToken(req3) {
		t.Error("validateCSRFToken should reject invalid token")
	}
}

func TestRequireCSRF(t *testing.T) {
	a := newTestApp(t)
	csrfSecret = []byte("test-secret-key-32-bytes-long!!!")

	called := false
	h := a.requireCSRF(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	})

	// GET should pass without CSRF
	called = false
	getReq := httptest.NewRequest(http.MethodGet, "/", nil)
	getRR := httptest.NewRecorder()
	h(getRR, getReq)
	if !called || getRR.Code != http.StatusNoContent {
		t.Error("requireCSRF should allow GET without token")
	}

	// POST without token should fail
	called = false
	postReq := httptest.NewRequest(http.MethodPost, "/", nil)
	postRR := httptest.NewRecorder()
	h(postRR, postReq)
	if called || postRR.Code != http.StatusForbidden {
		t.Error("requireCSRF should reject POST without token")
	}

	// POST with valid token should pass
	sessionToken := "session-xyz"
	token := generateCSRFToken(sessionToken)
	form := url.Values{"_csrf": []string{token}}
	postReq2 := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
	postReq2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	postReq2.AddCookie(&http.Cookie{Name: "warp_admin", Value: sessionToken})
	postRR2 := httptest.NewRecorder()
	called = false
	h(postRR2, postReq2)
	if !called || postRR2.Code != http.StatusNoContent {
		t.Error("requireCSRF should allow POST with valid token")
	}
}

// ============================================================================
// Auth Handlers Tests
// ============================================================================

func TestHandleAdminLoginSubmit(t *testing.T) {
	a := newTestApp(t)

	hash, err := bcrypt.GenerateFromPassword([]byte("pass123456"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}
	_, err = a.repo.db.Exec("INSERT INTO users(username, password_hash, created_at) VALUES(?, ?, ?)", "admin", string(hash), nowRFC3339())
	if err != nil {
		t.Fatal(err)
	}

	t.Run("invalid credentials", func(t *testing.T) {
		form := url.Values{"username": []string{"admin"}, "password": []string{"wrong"}}
		req := httptest.NewRequest(http.MethodPost, "/test-admin/login", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		a.handleAdminLoginSubmit(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
		}
		if !strings.Contains(rr.Body.String(), "Invalid credentials") {
			t.Error("expected invalid credentials message")
		}
	})

	t.Run("successful login", func(t *testing.T) {
		form := url.Values{"username": []string{"admin"}, "password": []string{"pass123456"}}
		req := httptest.NewRequest(http.MethodPost, "/test-admin/login", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		a.handleAdminLoginSubmit(rr, req)

		if rr.Code != http.StatusSeeOther {
			t.Errorf("status = %d, want %d", rr.Code, http.StatusSeeOther)
		}
		cookies := rr.Result().Cookies()
		var found bool
		for _, c := range cookies {
			if c.Name == "warp_admin" && c.Value != "" {
				found = true
			}
		}
		if !found {
			t.Error("expected warp_admin cookie to be set")
		}
	})
}

func TestHandleAdminLoginSubmitRateLimit(t *testing.T) {
	a := newTestApp(t)

	loginAttempts.Lock()
	loginAttempts.m = make(map[string]*loginAttempt)
	loginAttempts.m["192.0.2.1"] = &loginAttempt{
		count:       3,
		lastFail:    time.Now(),
		lockedUntil: time.Now().Add(15 * time.Second),
	}
	loginAttempts.Unlock()

	form := url.Values{"username": []string{"admin"}, "password": []string{"pass"}}
	req := httptest.NewRequest(http.MethodPost, "/test-admin/login", strings.NewReader(form.Encode()))
	req.RemoteAddr = "192.0.2.1:1234"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	a.handleAdminLoginSubmit(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	if rr.Header().Get("Retry-After") == "" {
		t.Error("expected Retry-After header")
	}
}

func TestHandleAdminLogout(t *testing.T) {
	a := newTestApp(t)

	_, err := a.repo.db.Exec("INSERT INTO users(id, username, password_hash, created_at) VALUES(1, 'admin', 'hash', ?)", nowRFC3339())
	if err != nil {
		t.Fatal(err)
	}

	sessionToken := "logout-token"
	if err := a.repo.CreateSession(context.Background(), 1, sha256Hex(sessionToken), time.Hour); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/test-admin/logout", nil)
	req.AddCookie(&http.Cookie{Name: "warp_admin", Value: sessionToken})
	rr := httptest.NewRecorder()

	a.handleAdminLogout(rr, req)

	if rr.Code != http.StatusSeeOther {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusSeeOther)
	}
	if !strings.Contains(rr.Header().Get("Location"), "/login") {
		t.Errorf("Location = %q, want login redirect", rr.Header().Get("Location"))
	}

	_, err = a.repo.GetSessionUser(context.Background(), sha256Hex(sessionToken))
	if err == nil {
		t.Error("expected session to be revoked")
	}
}

func TestCurrentUserID(t *testing.T) {
	a := newTestApp(t)

	_, err := a.repo.db.Exec("INSERT INTO users(id, username, password_hash, created_at) VALUES(1, 'admin', 'hash', ?)", nowRFC3339())
	if err != nil {
		t.Fatal(err)
	}

	sessionToken := "session-token"
	if err := a.repo.CreateSession(context.Background(), 1, sha256Hex(sessionToken), time.Hour); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "warp_admin", Value: sessionToken})
	uid, ok := a.currentUserID(req)
	if !ok || uid != 1 {
		t.Errorf("currentUserID = (%d, %v), want (1, true)", uid, ok)
	}

	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	if _, ok := a.currentUserID(req2); ok {
		t.Error("currentUserID should fail without cookie")
	}
}

// ============================================================================
// Cleanup Goroutine Coverage
// ============================================================================

func TestCleanupGoroutinesExit(t *testing.T) {
	oldShutdown := shutdownChan
	shutdownChan = make(chan struct{})
	close(shutdownChan)
	defer func() { shutdownChan = oldShutdown }()

	cleanupLoginAttempts()

	a := newTestApp(t)
	a.cleanupExpiredSessions()
	a.cleanupExpiredLinks()
}

func TestCleanupOrphanedUploads(t *testing.T) {
	a := newTestApp(t)
	ctx := context.Background()

	_, err := a.repo.db.Exec("INSERT INTO users(id, username, password_hash, created_at) VALUES(1, 'admin', 'hash', ?)", nowRFC3339())
	if err != nil {
		t.Fatal(err)
	}

	relPath := "uploads/orphan.txt"
	abs := filepath.Join(a.cfg.MediaRoot, relPath)
	if err := os.MkdirAll(filepath.Dir(abs), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(abs, []byte("orphan"), 0644); err != nil {
		t.Fatal(err)
	}

	_, err = a.repo.CreateShare(ctx, "orphanslug12", relPath, 1, true)
	if err != nil {
		t.Fatal(err)
	}

	a.cleanupOrphanedUploads(ctx)

	if _, err := os.Stat(abs); !os.IsNotExist(err) {
		t.Errorf("expected file to be deleted, err=%v", err)
	}

	if _, err := a.repo.GetShareRelPath(ctx, "orphanslug12"); err == nil {
		t.Error("expected share to be deleted")
	}
}

func TestCleanupOrphanedUploadsSkips(t *testing.T) {
	a := newTestApp(t)
	ctx := context.Background()

	_, err := a.repo.db.Exec("INSERT INTO users(id, username, password_hash, created_at) VALUES(1, 'admin', 'hash', ?)", nowRFC3339())
	if err != nil {
		t.Fatal(err)
	}

	// directory should be skipped
	dirRel := "uploads/dir"
	if err := os.MkdirAll(filepath.Join(a.cfg.MediaRoot, dirRel), 0755); err != nil {
		t.Fatal(err)
	}
	_, err = a.repo.CreateShare(ctx, "dirslug1234", dirRel, 1, true)
	if err != nil {
		t.Fatal(err)
	}

	// invalid path should be skipped
	_, err = a.repo.CreateShare(ctx, "badslug123", "bad\\path", 1, true)
	if err != nil {
		t.Fatal(err)
	}

	a.cleanupOrphanedUploads(ctx)

	// shares should still exist
	if _, err := a.repo.GetShareRelPath(ctx, "dirslug1234"); err != nil {
		t.Errorf("expected dir share to remain, err=%v", err)
	}
	if _, err := a.repo.GetShareRelPath(ctx, "badslug123"); err != nil {
		t.Errorf("expected bad path share to remain, err=%v", err)
	}
}

func TestCleanupLoginAttemptsTicker(t *testing.T) {
	oldShutdown := shutdownChan
	shutdownChan = make(chan struct{})
	defer func() { shutdownChan = oldShutdown }()

	oldTicker := newTicker
	newTicker = func(d time.Duration) *time.Ticker { return time.NewTicker(10 * time.Millisecond) }
	defer func() { newTicker = oldTicker }()

	loginAttempts.Lock()
	loginAttempts.m = map[string]*loginAttempt{
		"1.2.3.4": {count: 1, lastFail: time.Now().Add(-time.Hour), lockedUntil: time.Now().Add(-time.Minute)},
	}
	loginAttempts.Unlock()

	done := make(chan struct{})
	go func() {
		cleanupLoginAttempts()
		close(done)
	}()

	time.Sleep(20 * time.Millisecond)
	close(shutdownChan)

	select {
	case <-done:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("cleanupLoginAttempts did not exit")
	}

	loginAttempts.RLock()
	_, exists := loginAttempts.m["1.2.3.4"]
	loginAttempts.RUnlock()
	if exists {
		t.Error("expected stale login attempt to be removed")
	}
}

func TestCleanupExpiredSessionsAndLinksTicker(t *testing.T) {
	a := newTestApp(t)

	oldShutdown := shutdownChan
	shutdownChan = make(chan struct{})
	defer func() { shutdownChan = oldShutdown }()

	oldTicker := newTicker
	newTicker = func(d time.Duration) *time.Ticker { return time.NewTicker(10 * time.Millisecond) }
	defer func() { newTicker = oldTicker }()

	done1 := make(chan struct{})
	go func() {
		a.cleanupExpiredSessions()
		close(done1)
	}()

	done2 := make(chan struct{})
	go func() {
		a.cleanupExpiredLinks()
		close(done2)
	}()

	time.Sleep(20 * time.Millisecond)
	close(shutdownChan)

	select {
	case <-done1:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("cleanupExpiredSessions did not exit")
	}
	select {
	case <-done2:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("cleanupExpiredLinks did not exit")
	}
}
