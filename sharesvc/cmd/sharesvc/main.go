package main

import (
	"bytes"
	"context"
	"database/sql"
	"embed"
	"errors"
	"html/template"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"unicode/utf8"

	"github.com/go-webauthn/webauthn/webauthn"
	_ "modernc.org/sqlite"
)

// Shutdown signal for goroutines (used by auth.go)
var shutdownChan = make(chan struct{})

var signalNotify = signal.Notify
var signalStop = signal.Stop
var makeSignalChan = func() chan os.Signal { return make(chan os.Signal, 1) }

//go:embed assets/*.html assets/*.js assets/*.css
var content embed.FS

type app struct {
	cfg         config
	repo        *Repository
	sl          *SpeedLimiter
	tmplLogin   *template.Template
	tmplAdmin   *template.Template
	tmplBrowse  *template.Template
	tmplLanding *template.Template
	webauthn    *webauthn.WebAuthn
}

func main() {
	cfg, err := loadConfig()
	if err != nil {
		log.Fatal(err)
	}

	if err := os.MkdirAll(cfg.DataDir, 0o750); err != nil {
		log.Fatalf("mkdir data dir: %v", err)
	}

	// Initialize CSRF secret
	initCSRF(cfg.DataDir)

	// Open database with busy_timeout in connection string to ensure it applies to all connections.
	// This is more reliable with modernc.org/sqlite than setting it via PRAGMA afterwards.
	// 3000ms timeout prevents SQLITE_BUSY errors under concurrent load.
	db, err := sql.Open("sqlite", cfg.DBPath+"?_pragma=busy_timeout(3000)")
	if err != nil {
		log.Fatalf("open db: %v", err)
	}
	defer func() { _ = db.Close() }()

	// WAL mode allows multiple readers + one writer concurrently
	// 5 connections provides good balance between performance and resource usage
	db.SetMaxOpenConns(5)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(0)

	repo := NewRepository(db)
	if err := repo.InitDB(); err != nil {
		log.Fatalf("init db: %v", err)
	}
	generatedPass, err := repo.BootstrapAdmin(cfg.BootstrapAdminUser, cfg.BootstrapAdminPass)
	if err != nil {
		log.Fatalf("bootstrap admin: %v", err)
	}
	if generatedPass != "" {
		passPath := filepath.Join(cfg.DataDir, "bootstrap_admin_password")
		if err := os.WriteFile(passPath, []byte(generatedPass+"\n"), 0o600); err != nil {
			log.Printf("WARNING: failed to persist generated admin password: %v", err)
			log.Printf("  Set BOOTSTRAP_ADMIN_PASSWORD and restart to bootstrap safely.")
		} else {
			log.Printf("  One-time admin password written to: %s", passPath)
		}
		log.Printf("════════════════════════════════════════════════════════════════")
		log.Printf("  INITIAL ADMIN CREDENTIALS GENERATED")
		log.Printf("  Username: %s", cfg.BootstrapAdminUser)
		log.Printf("  Admin URL: %s%s/", cfg.PublicBase, cfg.AdminPath)
		log.Printf("")
		log.Printf("  IMPORTANT: LOG INTO THE ADMIN INTERFACE AND CHANGE THE PASSWORD!")
		log.Printf("  Delete the password file after first login.")
		log.Printf("════════════════════════════════════════════════════════════════")
	}

	rootResolved, err := filepath.EvalSymlinks(cfg.MediaRoot)
	if err != nil {
		log.Fatalf("media root invalid: %v", err)
	}
	cfg.MediaRoot = rootResolved

	// Cleanup any leftover temp files from previous crashes
	if cfg.UploadTempDir != "" {
		cleanupTempDir(cfg.UploadTempDir)
	}

	sl := NewSpeedLimiter()
	sl.Start(cfg.DataDir, shutdownChan)

	wa, err := initWebAuthn(cfg)
	if err != nil {
		log.Fatalf("init webauthn: %v", err)
	}

	a := &app{
		cfg:       cfg,
		repo:      repo,
		sl:        sl,
		tmplLogin: template.Must(template.ParseFS(content, "assets/login.html")),
		tmplAdmin: template.Must(template.New("admin.html").Funcs(template.FuncMap{
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
				// humanize.Time() returns strings like "3 days from now"
				// Just return as-is for English UI
				return s
			},
		}).ParseFS(content, "assets/admin.html")),
		tmplBrowse:  template.Must(template.ParseFS(content, "assets/browse.html")),
		tmplLanding: template.Must(template.ParseFS(content, "assets/landing.html")),
		webauthn:    wa,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", a.handleHealth)
	mux.HandleFunc("GET /warp-share.js", a.handlePublicAppJS)
	mux.HandleFunc("GET /warp-share.css", a.handlePublicCSS)
	mux.HandleFunc("GET /", a.handleRoot)
	mux.HandleFunc("GET "+cfg.AdminPath+"/", a.requireAdmin(a.handleAdminHome))
	mux.HandleFunc("GET "+cfg.AdminPath+"/static/app.js", a.handleAdminStaticAppJS)           // No auth - just static JS
	mux.HandleFunc("GET "+cfg.AdminPath+"/static/admin.css", a.handleAdminStaticCSS)          // No auth - just static CSS
	mux.HandleFunc("GET "+cfg.AdminPath+"/static/base.css", a.handleAdminStaticBaseCSS)       // No auth - needed for login page
	mux.HandleFunc("GET "+cfg.AdminPath+"/static/browse.css", a.handleAdminStaticBrowseCSS)   // No auth - just static CSS
	mux.HandleFunc("GET "+cfg.AdminPath+"/static/login.css", a.handleAdminStaticLoginCSS)     // No auth - needed for login page
	mux.HandleFunc("GET "+cfg.AdminPath+"/static/login.js", a.handleAdminStaticLoginJS)       // No auth - needed for login page
	mux.HandleFunc("POST "+cfg.AdminPath+"/create", a.requireAdmin(a.requireCSRF(a.handleAdminCreate)))
	mux.HandleFunc("POST "+cfg.AdminPath+"/quick_create", a.requireAdmin(a.handleAdminQuickCreate))
	mux.HandleFunc("POST "+cfg.AdminPath+"/disable", a.requireAdmin(a.requireCSRF(a.handleAdminDisableLink)))
	mux.HandleFunc("POST "+cfg.AdminPath+"/delete_link", a.requireAdmin(a.requireCSRF(a.handleAdminDeleteLink)))
	mux.HandleFunc("POST "+cfg.AdminPath+"/cleanup_links", a.requireAdmin(a.requireCSRF(a.handleAdminCleanupLinks)))
	mux.HandleFunc("POST "+cfg.AdminPath+"/password", a.requireAdmin(a.requireCSRF(a.handleAdminChangePassword)))
	mux.HandleFunc("GET "+cfg.AdminPath+"/browse", a.requireAdmin(a.handleAdminBrowse))
	mux.HandleFunc("POST "+cfg.AdminPath+"/upload", a.requireAdmin(a.requireCSRF(a.handleAdminUpload)))
	mux.HandleFunc("GET "+cfg.AdminPath+"/logout", a.handleAdminLogout)
	mux.HandleFunc("GET "+cfg.AdminPath+"/login", a.handleAdminLoginForm)
	mux.HandleFunc("POST "+cfg.AdminPath+"/login", a.handleAdminLoginSubmit)
	mux.HandleFunc("GET "+cfg.AdminPath+"/passkeys", a.requireAdmin(a.handlePasskeyList))
	mux.HandleFunc("POST "+cfg.AdminPath+"/passkeys/register/start", a.requireAdmin(a.requireCSRF(a.handlePasskeyRegisterStart)))
	mux.HandleFunc("POST "+cfg.AdminPath+"/passkeys/register/finish", a.requireAdmin(a.requireCSRF(a.handlePasskeyRegisterFinish)))
	mux.HandleFunc("POST "+cfg.AdminPath+"/passkeys/delete", a.requireAdmin(a.requireCSRF(a.handlePasskeyDelete)))
	mux.HandleFunc("POST "+cfg.AdminPath+"/passkeys/login/start", a.handlePasskeyLoginStart)
	mux.HandleFunc("POST "+cfg.AdminPath+"/passkeys/login/finish", a.handlePasskeyLoginFinish)
	mux.HandleFunc("POST "+cfg.AdminPath+"/speed_limit", a.requireAdmin(a.requireCSRF(a.handleAdminSpeedLimit)))

	go a.cleanupExpiredSessions()
	go a.cleanupExpiredLinks()
	go a.cleanupExpiredWebAuthnChallenges()
	go cleanupLoginAttempts()

	// Signal handling for graceful shutdown
	sigChan := makeSignalChan()
	signalNotify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	defer signalStop(sigChan)

	server := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           a.requestLog(mux),
		ReadHeaderTimeout: cfg.ServerReadHeaderTimeout,
		ReadTimeout:       cfg.ServerReadTimeout,
		// Security Note: WriteTimeout is intentionally set to 0 (unlimited) to support
		// large file downloads that may take hours. This is acceptable because:
		// - nginx reverse proxy has its own timeouts configured
		// - ReadTimeout prevents slowloris attacks on the request side
		// - Application is designed for file sharing with potentially large files
		WriteTimeout:      cfg.ServerWriteTimeout,
		IdleTimeout:       cfg.ServerIdleTimeout,
	}

	// Start server in goroutine
	go func() {
		log.Printf("warp-share listening on %s (admin at %s)", cfg.ListenAddr, cfg.AdminPath+"/")
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatal(err)
		}
	}()

	// Wait for shutdown signal
	sig := <-sigChan
	log.Printf("Received signal %v, initiating graceful shutdown...", sig)

	// Signal all goroutines to stop
	close(shutdownChan)

	// Give the server a grace period to finish active requests
	ctx, cancel := context.WithTimeout(context.Background(), cfg.ServerShutdownTimeout)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Printf("Server shutdown error: %v", err)
	}

	log.Println("Shutdown complete")
}

var bufPool = sync.Pool{
	New: func() any {
		return new(bytes.Buffer)
	},
}

func (a *app) render(w http.ResponseWriter, tmpl *template.Template, data any) {
	buf := bufPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer bufPool.Put(buf)

	if err := tmpl.Execute(buf, data); err != nil {
		log.Printf("render error: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	_, _ = w.Write(buf.Bytes())
}

// cleanupTempDir removes all files from the temp directory on startup.
// This is safe because no uploads can be active when the server starts.
func cleanupTempDir(tempDir string) {
	entries, err := os.ReadDir(tempDir)
	if err != nil {
		if os.IsNotExist(err) {
			return // Directory doesn't exist yet, nothing to clean
		}
		log.Printf("Warning: could not read temp dir %s: %v", tempDir, err)
		return
	}

	var cleaned int
	for _, entry := range entries {
		path := filepath.Join(tempDir, entry.Name())
		if entry.IsDir() {
			if err := os.RemoveAll(path); err != nil {
				log.Printf("Warning: could not remove temp dir %s: %v", path, err)
			} else {
				cleaned++
			}
		} else {
			if err := os.Remove(path); err != nil {
				log.Printf("Warning: could not remove temp file %s: %v", path, err)
			} else {
				cleaned++
			}
		}
	}

	if cleaned > 0 {
		log.Printf("Cleaned up %d orphaned item(s) from temp directory", cleaned)
	}
}
