package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// CSRF secret (persisted)
var csrfSecret []byte

func initCSRF(dataDir string) {
	keyFile := filepath.Join(dataDir, "csrf.key")

	// Try to read existing key
	key, err := os.ReadFile(keyFile)
	if err == nil && len(key) == 32 {
		csrfSecret = key
		// log.Println("Loaded persisted CSRF secret")
		return
	}

	// Generate new key
	csrfSecret = make([]byte, 32)
	if _, err := randRead(csrfSecret); err != nil {
		panic("failed to generate CSRF secret: " + err.Error())
	}

	// Save key
	if err := os.WriteFile(keyFile, csrfSecret, 0600); err != nil {
		log.Printf("WARNING: failed to persist CSRF secret: %v", err)
	} else {
		log.Println("Generated and persisted new CSRF secret")
	}
}

// Rate limiting for login with automatic cleanup
var loginAttempts = struct {
	sync.RWMutex
	m map[string]*loginAttempt
}{m: make(map[string]*loginAttempt)}

var newTicker = time.NewTicker

type loginAttempt struct {
	count       int
	lastFail    time.Time
	lockedUntil time.Time
}

// cleanupLoginAttempts removes old entries from the rate-limit map
func cleanupLoginAttempts() {
	ticker := newTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-shutdownChan:
			return
		case <-ticker.C:
			now := time.Now()
			loginAttempts.Lock()
			for ip, attempt := range loginAttempts.m {
				// Remove entries older than 30 minutes that are no longer locked
				if now.Sub(attempt.lastFail) > 30*time.Minute && now.After(attempt.lockedUntil) {
					delete(loginAttempts.m, ip)
				}
			}
			count := len(loginAttempts.m)
			loginAttempts.Unlock()
			if count > 0 {
				log.Printf("Rate-limit map: %d active entries", count)
			}
		}
	}
}

// checkLoginRateLimit checks if an IP has too many login attempts
func checkLoginRateLimit(ip string) (allowed bool, retryAfter time.Duration) {
	loginAttempts.Lock()
	defer loginAttempts.Unlock()

	attempt, exists := loginAttempts.m[ip]
	now := time.Now()

	if !exists {
		loginAttempts.m[ip] = &loginAttempt{count: 0, lastFail: time.Time{}}
		return true, 0
	}

	// If locked, check if lock has expired
	if !attempt.lockedUntil.IsZero() && now.Before(attempt.lockedUntil) {
		return false, attempt.lockedUntil.Sub(now)
	}

	// Reset after 15 minutes without failures
	if now.Sub(attempt.lastFail) > 15*time.Minute {
		attempt.count = 0
		attempt.lockedUntil = time.Time{}
	}

	return true, 0
}

// recordLoginFailure records a failed login attempt
func recordLoginFailure(ip string) {
	loginAttempts.Lock()
	defer loginAttempts.Unlock()

	attempt, exists := loginAttempts.m[ip]
	if !exists {
		attempt = &loginAttempt{}
		loginAttempts.m[ip] = attempt
	}

	attempt.count++
	attempt.lastFail = time.Now()

	// Exponential backoff: 5, 15, 30, 60, 120 seconds...
	switch {
	case attempt.count >= 10:
		attempt.lockedUntil = time.Now().Add(5 * time.Minute)
	case attempt.count >= 7:
		attempt.lockedUntil = time.Now().Add(2 * time.Minute)
	case attempt.count >= 5:
		attempt.lockedUntil = time.Now().Add(60 * time.Second)
	case attempt.count >= 3:
		attempt.lockedUntil = time.Now().Add(15 * time.Second)
	}
}

// clearLoginFailures resets the failure count after successful login
func clearLoginFailures(ip string) {
	loginAttempts.Lock()
	defer loginAttempts.Unlock()
	delete(loginAttempts.m, ip)
}

func (a *app) handleAdminLoginForm(w http.ResponseWriter, r *http.Request) {
	a.render(w, a.tmplLogin, map[string]any{
		"AdminPath": a.cfg.AdminPath,
		"Error":     "",
	})
}

func (a *app) handleAdminLoginSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.NotFound(w, r)
		return
	}

	clientIP := getClientIP(r)

	// Check rate limit
	allowed, retryAfter := checkLoginRateLimit(clientIP)
	if !allowed {
		w.Header().Set("Retry-After", strconv.Itoa(int(retryAfter.Seconds())))
		a.render(w, a.tmplLogin, map[string]any{
			"AdminPath": a.cfg.AdminPath,
			"Error":     fmt.Sprintf("Too many attempts. Please wait %d seconds.", int(retryAfter.Seconds())),
		})
		return
	}

	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")

	uid, err := a.repo.AuthenticateUser(r.Context(), username, password)
	if err != nil {
		recordLoginFailure(clientIP)
		log.Printf("LOGIN FAILED: ip=%s user=%s reason=auth_error", clientIP, username)
		a.render(w, a.tmplLogin, map[string]any{"AdminPath": a.cfg.AdminPath, "Error": "Invalid credentials"})
		return
	}

	// Check if password change is required (negative uid indicates must_change_password=1)
	mustChangePassword := false
	if uid < 0 {
		mustChangePassword = true
		uid = -uid // Convert back to positive user ID
	}

	// Successful login
	clearLoginFailures(clientIP)
	log.Printf("LOGIN SUCCESS: ip=%s user=%s must_change=%v", clientIP, username, mustChangePassword)

	sessToken, err := randomToken(32)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	if err := a.repo.CreateSession(r.Context(), uid, sha256Hex(sessToken), a.cfg.SessionTTL); err != nil {
		log.Printf("Session create error: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	exp := time.Now().Add(a.cfg.SessionTTL)
	http.SetCookie(w, &http.Cookie{
		Name:     "warp_admin",
		Value:    sessToken,
		Path:     a.cfg.AdminPath + "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode, // Strict for better CSRF protection
		// Security Note: Expires field is intentionally set for compatibility.
		// The session TTL is primarily enforced server-side via database expiration.
		// This client-side Expires acts as a hint to browsers and complements MaxAge.
		Expires:  exp,
	})

	// If password change is required, redirect to settings tab with notice
	if mustChangePassword {
		http.Redirect(w, r, a.cfg.AdminPath+"/?tab=settings&must_change=1", http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, a.cfg.AdminPath+"/", http.StatusSeeOther)
}

func (a *app) handleAdminLogout(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("warp_admin")
	if err == nil && strings.TrimSpace(c.Value) != "" {
		_ = a.repo.RevokeSession(r.Context(), sha256Hex(c.Value))
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "warp_admin",
		Value:    "",
		Path:     a.cfg.AdminPath + "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
	})
	http.Redirect(w, r, a.cfg.AdminPath+"/login", http.StatusSeeOther)
}

func (a *app) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		uid, ok := a.currentUserID(r)
		if !ok {
			http.Redirect(w, r, a.cfg.AdminPath+"/login", http.StatusSeeOther)
			return
		}
		r = r.WithContext(context.WithValue(r.Context(), ctxKeyUserID{}, uid))
		next(w, r)
	}
}

type ctxKeyUserID struct{}

func (a *app) currentUserID(r *http.Request) (int64, bool) {
	c, err := r.Cookie("warp_admin")
	if err != nil || strings.TrimSpace(c.Value) == "" {
		return 0, false
	}
	th := sha256Hex(c.Value)
	uid, err := a.repo.GetSessionUser(r.Context(), th)
	if err != nil {
		return 0, false
	}
	return uid, true
}

// cleanupExpiredSessions periodically removes expired sessions from the database
func (a *app) cleanupExpiredSessions() {
	ticker := newTicker(1 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-shutdownChan:
			log.Println("Session cleanup goroutine shutting down")
			return
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			deleted, err := a.repo.CleanupExpiredSessions(ctx)
			cancel()
			if err == nil {
				if deleted > 0 {
					log.Printf("Cleaned up %d expired sessions", deleted)
				}
			}
		}
	}
}

// cleanupExpiredLinks periodically removes expired and exhausted links from the database
func (a *app) cleanupExpiredLinks() {
	ticker := newTicker(6 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-shutdownChan:
			log.Println("Link cleanup goroutine shutting down")
			return
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			deleted, err := a.repo.CleanupExpiredLinks(ctx)
			if err == nil && deleted > 0 {
				log.Printf("Cleaned up %d expired/used links", deleted)
			}
			// Remove uploaded files that no longer have active links
			a.cleanupOrphanedUploads(ctx)
			// Also clean up orphaned shares
			deletedShares, err := a.repo.CleanupOrphanedShares(ctx)
			cancel()
			if err == nil && deletedShares > 0 {
				log.Printf("Cleaned up %d orphaned shares", deletedShares)
			}
		}
	}
}

func (a *app) cleanupOrphanedUploads(ctx context.Context) {
	items, err := a.repo.ListOrphanedUploadShares(ctx, 200)
	if err != nil || len(items) == 0 {
		return
	}

	for _, it := range items {
		abs, err := safeJoinAndCheck(a.cfg.MediaRoot, it.RelPath)
		if err != nil {
			log.Printf("UPLOAD CLEANUP: invalid path rel=%s err=%v", it.RelPath, err)
			continue
		}
		if fi, err := os.Stat(abs); err == nil && fi.IsDir() {
			log.Printf("UPLOAD CLEANUP: skip directory rel=%s", it.RelPath)
			continue
		}
		if err := os.Remove(abs); err != nil && !os.IsNotExist(err) {
			log.Printf("UPLOAD CLEANUP: delete failed rel=%s err=%v", it.RelPath, err)
			continue
		}
		if err := a.repo.DeleteShare(ctx, it.ID); err != nil {
			log.Printf("UPLOAD CLEANUP: db delete failed id=%d rel=%s err=%v", it.ID, it.RelPath, err)
			continue
		}
		log.Printf("UPLOAD CLEANUP: deleted rel=%s", it.RelPath)
	}
}

// generateCSRFToken creates a CSRF token based on the session cookie
func generateCSRFToken(sessionToken string) string {
	h := sha256.New()
	h.Write(csrfSecret)
	h.Write([]byte(sessionToken))
	return hex.EncodeToString(h.Sum(nil))[:32]
}

// validateCSRFToken validates the CSRF token using constant-time comparison.
// For multipart requests (file uploads), only the header is checked,
// since FormValue() would parse the body and MultipartReader() would no longer work.
func (a *app) validateCSRFToken(r *http.Request) bool {
	c, err := r.Cookie("warp_admin")
	if err != nil || strings.TrimSpace(c.Value) == "" {
		return false
	}
	expected := generateCSRFToken(c.Value)

	var actual string
	// For multipart requests, only use header (FormValue would call ParseMultipartForm)
	contentType := r.Header.Get("Content-Type")
	if strings.HasPrefix(contentType, "multipart/form-data") {
		actual = r.Header.Get("X-CSRF-Token")
	} else {
		actual = r.FormValue("_csrf")
		if actual == "" {
			actual = r.Header.Get("X-CSRF-Token")
		}
	}

	// Constant-time comparison prevents timing attacks
	if len(actual) != len(expected) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(actual), []byte(expected)) == 1
}

// requireCSRF is a wrapper that enforces CSRF validation
func (a *app) requireCSRF(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			if !a.validateCSRFToken(r) {
				log.Printf("CSRF FAILED: ip=%s path=%s", getClientIP(r), r.URL.Path)
				http.Error(w, "Invalid request", http.StatusForbidden)
				return
			}
		}
		next(w, r)
	}
}
