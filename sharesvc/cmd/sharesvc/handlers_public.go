package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/dustin/go-humanize"
)

func (a *app) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

func (a *app) handlePublicAppJS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	data, _ := content.ReadFile("assets/public.js")
	_, _ = w.Write(data)
}

func (a *app) handlePublicCSS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	baseCSS, _ := content.ReadFile("assets/base.css")
	landingCSS, _ := content.ReadFile("assets/landing.css")
	_, _ = w.Write(baseCSS)
	_, _ = w.Write(landingCSS)
}

func (a *app) handleServiceWorker(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Service-Worker-Allowed", "/")
	data, _ := content.ReadFile("assets/sw.js")
	_, _ = w.Write(data)
}

func (a *app) handleRoot(w http.ResponseWriter, r *http.Request) {
	// Only two-segment paths are considered download links: /<share>/<token>
	trimmed := strings.Trim(r.URL.Path, "/")
	if trimmed == "" {
		http.NotFound(w, r)
		return
	}

	parts := strings.Split(trimmed, "/")
	if len(parts) != 2 {
		http.NotFound(w, r)
		return
	}

	shareSlug := parts[0]
	token := parts[1]
	if !looksLikeToken(shareSlug, 12) || !looksLikeToken(token, 20) {
		http.NotFound(w, r)
		return
	}

	if r.URL.Query().Get("download") == "1" {
		a.handleDownload(w, r, shareSlug, token)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.NotFound(w, r)
		return
	}
	a.handleLanding(w, r, shareSlug, token)
}

func (a *app) handleDownload(w http.ResponseWriter, r *http.Request, shareSlug, token string) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.NotFound(w, r)
		return
	}

	clientIP := getClientIP(r)
	now := time.Now().UTC()
	tokenHash := sha256Hex(token)

	ctx, cancel := context.WithTimeout(r.Context(), a.cfg.DBTimeout)
	defer cancel()

	var (
		fileRelPath string
		ok          bool
	)
	if r.Method == http.MethodHead {
		fileRelPath, _, _, ok = a.repo.PeekLink(ctx, shareSlug, tokenHash, clientIP, now, a.cfg.GrantTTL)
	} else {
		fileRelPath, ok = a.repo.ConsumeLink(ctx, shareSlug, tokenHash, clientIP, now, a.cfg.GrantTTL)
	}
	if !ok {
		log.Printf("DOWNLOAD DENIED: ip=%s share=%s reason=invalid_or_expired", clientIP, shareSlug)
		http.NotFound(w, r)
		return
	}

	absPath, err := safeJoinAndCheck(a.cfg.MediaRoot, fileRelPath)
	if err != nil {
		log.Printf("DOWNLOAD DENIED: ip=%s share=%s reason=path_error file=%s", clientIP, shareSlug, fileRelPath)
		http.NotFound(w, r)
		return
	}

	log.Printf("DOWNLOAD START: ip=%s share=%s file=%s", clientIP, shareSlug, filepath.Base(fileRelPath))

	f, err := os.Open(absPath)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("DOWNLOAD DENIED: ip=%s share=%s reason=file_not_found file=%s", clientIP, shareSlug, fileRelPath)
		}
		http.NotFound(w, r)
		return
	}

	fi, err := f.Stat()
	if err != nil {
		_ = f.Close()
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", path.Base(fileRelPath)))

	// Track bytes written to detect completion
	cw := &countingWriter{ResponseWriter: w}
	// IMPORTANT: throttledFile wraps the file and MUST be closed to release IP counter
	throttled := a.sl.WrapFileWithIP(f, clientIP)
	defer func() { _ = throttled.Close() }() // This also closes f
	http.ServeContent(cw, r, path.Base(fileRelPath), fi.ModTime(), throttled)

	if r.Method == http.MethodGet {
		complete := r.Header.Get("Range") == "" && cw.written == fi.Size()
		log.Printf("DOWNLOAD END: ip=%s share=%s file=%s bytes=%d complete=%t", clientIP, shareSlug, filepath.Base(fileRelPath), cw.written, complete)
	}
}

type countingWriter struct {
	http.ResponseWriter
	written int64
}

func (c *countingWriter) Write(b []byte) (int, error) {
	n, err := c.ResponseWriter.Write(b)
	c.written += int64(n)
	return n, err
}

func (c *countingWriter) Flush() {
	flushResponseWriter(c.ResponseWriter)
}

func (c *countingWriter) Unwrap() http.ResponseWriter {
	return c.ResponseWriter
}

func (a *app) handleLanding(w http.ResponseWriter, r *http.Request, shareSlug, token string) {
	clientIP := getClientIP(r)
	now := time.Now().UTC()
	tokenHash := sha256Hex(token)

	ctx, cancel := context.WithTimeout(r.Context(), a.cfg.DBTimeout)
	defer cancel()

	fileRelPath, maxDL, usedDL, ok := a.repo.PeekLink(ctx, shareSlug, tokenHash, clientIP, now, a.cfg.GrantTTL)
	if !ok {
		http.NotFound(w, r)
		return
	}

	absPath, err := safeJoinAndCheck(a.cfg.MediaRoot, fileRelPath)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	fi, err := os.Stat(absPath)
	if err != nil || fi.IsDir() {
		http.NotFound(w, r)
		return
	}

	direct := fmt.Sprintf("%s%s?download=1", a.cfg.PublicBase, r.URL.Path)
	if r.URL.RawQuery != "" {
		// preserve any other query params
		direct = fmt.Sprintf("%s%s?%s&download=1", a.cfg.PublicBase, r.URL.Path, r.URL.RawQuery)
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	speedSchedule, speedCurrent := a.sl.Info(time.Now())
	a.render(w, a.tmplLanding, map[string]any{
		"FileName":      path.Base(fileRelPath),
		"Size":          humanize.Bytes(uint64(fi.Size())),
		"Remaining":     formatRemaining(maxDL, usedDL),
		"DownloadURL":   direct,
		"SpeedSchedule": speedSchedule,
		"SpeedCurrent":  speedCurrent,
		"PublicBase":    a.cfg.PublicBase,
	})
}
