package main

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image/color"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/dustin/go-humanize"
	"github.com/skip2/go-qrcode"
	"golang.org/x/crypto/bcrypt"
)

// redirectToAdmin redirects to admin path with optional tab and message
func (a *app) redirectToAdmin(w http.ResponseWriter, r *http.Request, tab, msg string) {
	path := a.cfg.AdminPath + "/"
	if tab != "" {
		path += "?tab=" + tab
		if msg != "" {
			path += "&msg=" + url.QueryEscape(msg)
		}
	} else if msg != "" {
		path += "?msg=" + url.QueryEscape(msg)
	}
	http.Redirect(w, r, path, http.StatusSeeOther)
}

type statsRecentActivity struct {
	RelPath            string
	IP                 string
	TimeFull           string
	TimeAgo            string
	Downloads          int64
	MaxDownloads       int64
	UsedDownloads      int64
	RemainingDownloads string
}

func (a *app) handleAdminHome(w http.ResponseWriter, r *http.Request) {
	tab := strings.TrimSpace(r.URL.Query().Get("tab"))
	if tab == "" {
		tab = "create"
	}

	var (
		statsTotalDownloads int64
		statsTotalShares    int64
		topFiles            []StatsTopFile
		recentActivity      []statsRecentActivity
	)

	if tab == "stats" {
		statsTotalDownloads, statsTotalShares, _ = a.repo.GetGlobalStats(r.Context())

		if tf, err := a.repo.GetTopFiles(r.Context()); err == nil {
			topFiles = tf
		}

		if ra, err := a.repo.GetRecentActivity(r.Context()); err == nil {
			for _, item := range ra {
				rec := statsRecentActivity{
					RelPath:            item.RelPath,
					IP:                 item.IP,
					Downloads:          item.Downloads,
					TimeFull:           item.LastAt,
					MaxDownloads:       item.MaxDownloads,
					UsedDownloads:      item.UsedDownloads,
					RemainingDownloads: formatRemaining(item.MaxDownloads, item.UsedDownloads),
				}
				if t, err := time.Parse(time.RFC3339, item.LastAt); err == nil {
					rec.TimeAgo = humanize.Time(t)
				} else {
					rec.TimeAgo = item.LastAt
				}
				recentActivity = append(recentActivity, rec)
			}
		}
	}

	links, _ := a.getLinks(r.Context())

	currentUsername := ""
	mustChangePassword := false
	if uidAny := r.Context().Value(ctxKeyUserID{}); uidAny != nil {
		if uid, ok := uidAny.(int64); ok && uid > 0 {
			if u, err := a.repo.GetUsernameByID(r.Context(), uid); err == nil {
				currentUsername = u
			}
			if mc, err := a.repo.MustChangePassword(r.Context(), uid); err == nil {
				mustChangePassword = mc
			}
		}
	}

	// Check if must_change=1 query parameter is set (redirected from login)
	if strings.TrimSpace(r.URL.Query().Get("must_change")) == "1" {
		mustChangePassword = true
	}

	created := strings.TrimSpace(r.URL.Query().Get("created"))
	createdQR := ""
	if created != "" {
		qr, err := qrcode.New(created, qrcode.Medium)
		if err == nil {
			qr.BackgroundColor = color.RGBA{0, 20, 40, 255}  // dark blue background
			qr.ForegroundColor = color.RGBA{0, 255, 255, 255} // cyan foreground
			if png, err := qr.PNG(220); err == nil {
				createdQR = base64.StdEncoding.EncodeToString(png)
			}
		}
	}

	speedSchedule, speedCurrent := a.sl.Info(time.Now())
	currentDefLimit, currentAltLimit, currentAltStart, currentAltEnd := a.sl.GetConfig()

	// Generate CSRF token for forms
	csrfToken := ""
	if c, err := r.Cookie("warp_admin"); err == nil && c.Value != "" {
		csrfToken = generateCSRFToken(c.Value)
	}

	a.render(w, a.tmplAdmin, map[string]any{
		"AdminPath":           a.cfg.AdminPath,
		"MediaRoot":           a.cfg.MediaRoot,
		"BrowseStartRel":      a.cfg.BrowseStartRel,
		"PublicBase":          a.cfg.PublicBase,
		"Tab":                 tab,
		"Created":             created,
		"CreatedQR":           createdQR,
		"Prefill":             strings.TrimSpace(r.URL.Query().Get("prefill")),
		"Msg":                 strings.TrimSpace(r.URL.Query().Get("msg")),
		"Links":               links,
		"SpeedSchedule":       speedSchedule,
		"SpeedCurrent":        speedCurrent,
		"CurrentDefLimit":     currentDefLimit,
		"CurrentAltLimit":     currentAltLimit,
		"CurrentAltStart":     currentAltStart,
		"CurrentAltEnd":       currentAltEnd,
		"CSRFToken":           csrfToken,
		"CurrentUsername":     currentUsername,
		"MustChangePassword":  mustChangePassword,
		"StatsTotalDownloads": statsTotalDownloads,
		"StatsTotalShares":    statsTotalShares,
		"StatsTopFiles":       topFiles,
		"StatsRecentActivity": recentActivity,
	})
}

func (a *app) handleAdminSpeedLimit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.NotFound(w, r)
		return
	}

	defStr := strings.TrimSpace(r.FormValue("default_limit"))
	altStr := strings.TrimSpace(r.FormValue("alt_limit"))
	startStr := strings.TrimSpace(r.FormValue("alt_start"))
	endStr := strings.TrimSpace(r.FormValue("alt_end"))

	defVal, err1 := strconv.ParseInt(defStr, 10, 64)
	altVal, err2 := strconv.ParseInt(altStr, 10, 64)
	startVal, err3 := strconv.ParseInt(startStr, 10, 64)
	endVal, err4 := strconv.ParseInt(endStr, 10, 64)

	if err1 != nil || err2 != nil || err3 != nil || err4 != nil || defVal < 0 || altVal < 0 || startVal < 0 || startVal > 23 || endVal < 0 || endVal > 23 {
		a.redirectToAdmin(w, r, "settings", "Invalid values")
		return
	}

	a.sl.SetLimits(defVal, altVal, startVal, endVal)

	configPath := filepath.Join(a.cfg.DataDir, "speed_limit.txt")
	if err := a.sl.WriteConfig(configPath, defVal, altVal, startVal, endVal); err != nil {
		log.Printf("ERROR: failed to persist speed config: %v", err)
		a.redirectToAdmin(w, r, "settings", "Active now (won't persist after restart)")
		return
	}

	log.Printf("SPEED CONFIG: default=%d alt=%d window=%02d:00-%02d:00", defVal, altVal, startVal, endVal)
	a.redirectToAdmin(w, r, "settings", "Speed settings saved")
}

func (a *app) handleAdminQuickCreate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.NotFound(w, r)
		return
	}
	// CSRF validation also required for AJAX requests (session cookie alone is not enough)
	if !a.validateCSRFToken(r) {
		jsonError(w, http.StatusForbidden, "csrf", "Invalid CSRF token")
		return
	}
	slug := strings.TrimSpace(r.FormValue("slug"))
	if !looksLikeToken(slug, 12) {
		jsonError(w, http.StatusBadRequest, "invalid_share", "Invalid share")
		return
	}

	if _, err := a.repo.GetShareRelPath(r.Context(), slug); err != nil {
		jsonError(w, http.StatusNotFound, "not_found", "Share not found")
		return
	}

	linkToken, err := randomToken(24)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "token", "Token generation failed")
		return
	}

	// Default quick link: 1 download, no expiry, no per-ip.
	maxDownloads := int64(1)
	if err := a.repo.CreateQuickLink(r.Context(), slug, sha256Hex(linkToken), maxDownloads); err != nil {
		jsonError(w, http.StatusInternalServerError, "db", "Database error")
		return
	}

	dl := fmt.Sprintf("%s/%s/%s", getBaseURL(r, a.cfg.PublicBase), slug, linkToken)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := json.NewEncoder(w).Encode(map[string]string{"url": dl}); err != nil {
		log.Printf("json encode error: %v", err)
	}
}

func (a *app) handleAdminStaticAppJS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	data, _ := content.ReadFile("assets/admin.js")
	_, _ = w.Write(data)
}

func (a *app) handleAdminStaticCSS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	data, _ := content.ReadFile("assets/admin.css")
	_, _ = w.Write(data)
}

func (a *app) handleAdminStaticBaseCSS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	data, _ := content.ReadFile("assets/base.css")
	_, _ = w.Write(data)
}

func (a *app) handleAdminStaticBrowseCSS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	data, _ := content.ReadFile("assets/browse.css")
	_, _ = w.Write(data)
}

func (a *app) handleAdminStaticLoginCSS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	data, _ := content.ReadFile("assets/login.css")
	_, _ = w.Write(data)
}

func (a *app) handleAdminChangePassword(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.NotFound(w, r)
		return
	}
	uidAny := r.Context().Value(ctxKeyUserID{})
	uid, _ := uidAny.(int64)
	if uid == 0 {
		http.NotFound(w, r)
		return
	}

	currentPassword := r.FormValue("current_password")
	if strings.TrimSpace(currentPassword) == "" {
		a.redirectToAdmin(w, r, "settings", "Current password required")
		return
	}

	currentUsername, err := a.repo.GetUsernameByID(r.Context(), uid)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if _, err := a.repo.AuthenticateUser(r.Context(), currentUsername, currentPassword); err != nil {
		a.redirectToAdmin(w, r, "settings", "Current password is incorrect")
		return
	}

	newUsername := strings.TrimSpace(r.FormValue("new_username"))
	if newUsername != "" {
		if len(newUsername) < 3 || len(newUsername) > 64 || !looksLikeToken(newUsername, 3) {
			a.redirectToAdmin(w, r, "settings", "Invalid username")
			return
		}
		if err := a.repo.UpdateUsername(uid, newUsername); err != nil {
			a.redirectToAdmin(w, r, "settings", "Could not change username")
			return
		}
	}

	new1 := r.FormValue("new_password")
	new2 := r.FormValue("new_password2")
	if new1 != "" || new2 != "" {
		if new1 == "" || new1 != new2 || len(new1) < 12 {
			a.redirectToAdmin(w, r, "settings", "Min 12 chars required, must match")
			return
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(new1), bcrypt.DefaultCost)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		if err := a.repo.UpdatePassword(uid, string(hash)); err != nil {
			http.NotFound(w, r)
			return
		}
	}

	a.redirectToAdmin(w, r, "settings", "Settings saved")
}

// linkRow represents a single link in the history
type linkRow struct {
	LinkID        int64
	ShareSlug     string
	RelPath       string
	CreatedAt     string
	Status        string
	ExpiresRel    string
	UsedDownloads int64
	MaxDownloads  string
	Remaining     string
}

// getLinks returns all links with their stats
func (a *app) getLinks(ctx context.Context) ([]linkRow, error) {
	rows, err := a.repo.ListLinksWithStats(ctx)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	var out []linkRow
	for _, l := range rows {
		// Format CreatedAt for better display (date on first line, time on second)
		createdFormatted := l.CreatedAt
		if t, err := time.Parse(time.RFC3339, l.CreatedAt); err == nil {
			createdFormatted = t.Format("2006-01-02\n15:04:05")
		}

		r := linkRow{
			LinkID:        l.LinkID,
			ShareSlug:     l.ShareSlug,
			RelPath:       l.FileRelPath,
			CreatedAt:     createdFormatted,
			UsedDownloads: l.UsedDownloads,
		}

		// MaxDownloads as string (∞ for unlimited)
		if l.MaxDownloads > 0 {
			r.MaxDownloads = fmt.Sprintf("%d", l.MaxDownloads)
		} else {
			r.MaxDownloads = "∞"
		}

		// Determine status
		isExpired := false
		if l.ExpiresAt.Valid {
			if t, err := time.Parse(time.RFC3339, l.ExpiresAt.String); err == nil {
				if !now.Before(t) {
					isExpired = true
				} else {
					r.ExpiresRel = humanize.Time(t)
				}
			}
		} else {
			r.ExpiresRel = "unlimited"
		}

		isExhausted := l.MaxDownloads > 0 && l.UsedDownloads >= l.MaxDownloads
		isDisabled := l.Disabled != 0

		if isDisabled {
			r.Status = "disabled"
			r.ExpiresRel = "-"
		} else if isExpired {
			r.Status = "expired"
			r.ExpiresRel = "expired"
		} else if isExhausted {
			r.Status = "exhausted"
			r.ExpiresRel = "-"
		} else {
			r.Status = "valid"
		}

		// Remaining downloads
		r.Remaining = formatRemaining(l.MaxDownloads, l.UsedDownloads)

		out = append(out, r)
	}
	return out, nil
}

func (a *app) handleAdminDisableLink(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.NotFound(w, r)
		return
	}
	id := parseInt64Default(r.FormValue("id"), 0)
	if id <= 0 {
		a.redirectToAdmin(w, r, "history", "Invalid link ID")
		return
	}
	_ = a.repo.DisableLink(r.Context(), id)
	a.redirectToAdmin(w, r, "history", "Link stopped")
}

func (a *app) handleAdminDeleteLink(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.NotFound(w, r)
		return
	}
	id := parseInt64Default(r.FormValue("id"), 0)
	if id <= 0 {
		a.redirectToAdmin(w, r, "history", "Invalid link ID")
		return
	}
	_ = a.repo.DeleteLink(r.Context(), id)
	a.redirectToAdmin(w, r, "history", "Link deleted")
}

func (a *app) handleAdminCleanupLinks(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.NotFound(w, r)
		return
	}
	count, err := a.repo.DeleteAllInactiveLinks(r.Context())
	if err != nil {
		a.redirectToAdmin(w, r, "history", "Cleanup failed")
		return
	}

	// Also cleanup orphaned uploads and shares immediately
	a.cleanupOrphanedUploads(r.Context())
	sharesDeleted, _ := a.repo.CleanupOrphanedSharesImmediate(r.Context())

	msg := fmt.Sprintf("%d inactive links deleted", count)
	if sharesDeleted > 0 {
		msg += fmt.Sprintf(", %d orphaned shares removed", sharesDeleted)
	}
	a.redirectToAdmin(w, r, "history", msg)
}

func (a *app) handleAdminBrowse(w http.ResponseWriter, r *http.Request) {
	dir := strings.TrimSpace(r.URL.Query().Get("dir"))
	dir = strings.TrimPrefix(dir, "/")
	pickMode := r.URL.Query().Get("pick") == "1"
	base := filepath.ToSlash(filepath.Clean(strings.TrimPrefix(a.cfg.BrowseStartRel, "/")))
	if base == "" {
		base = "."
	}
	if dir == "" || dir == "." {
		dir = base
	}
	if base != "." {
		if dir != base && !strings.HasPrefix(dir, base+"/") {
			http.NotFound(w, r)
			return
		}
	}
	abs, err := safeJoinAndCheck(a.cfg.MediaRoot, dir)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	entries, err := os.ReadDir(abs)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	type entry struct {
		Name    string
		Rel     string
		PickRel string
		IsDir   bool
	}
	var list []entry
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, ".") {
			continue
		}
		rel := filepath.ToSlash(filepath.Clean(filepath.Join(dir, name)))
		pickRel := rel
		if base != "." {
			if rel == base {
				pickRel = "."
			} else if strings.HasPrefix(rel, base+"/") {
				pickRel = strings.TrimPrefix(rel, base+"/")
			}
		}
		list = append(list, entry{Name: name, Rel: rel, PickRel: pickRel, IsDir: e.IsDir()})
	}

	parent := ""
	if dir != base {
		p := filepath.ToSlash(filepath.Clean(filepath.Dir(dir)))
		if base == "." {
			if p == "." {
				parent = "."
			} else {
				parent = p
			}
		} else {
			if p == base || strings.HasPrefix(p, base+"/") {
				parent = p
			}
		}
	}

	a.render(w, a.tmplBrowse, map[string]any{
		"AdminPath": a.cfg.AdminPath,
		"Dir":       dir,
		"Parent":    parent,
		"Entries":   list,
		"Pick":      pickMode,
	})
}

func (a *app) handleAdminCreate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.NotFound(w, r)
		return
	}

	rel := strings.TrimSpace(r.FormValue("relpath"))
	rel = strings.TrimPrefix(rel, "/")
	if rel == "" {
		a.redirectToAdmin(w, r, "", "")
		return
	}

	// Allow UI to specify paths relative to the browse base.
	base := filepath.ToSlash(filepath.Clean(strings.TrimPrefix(a.cfg.BrowseStartRel, "/")))
	if base != "" && base != "." {
		relClean := filepath.ToSlash(filepath.Clean(rel))
		if relClean != base && !strings.HasPrefix(relClean, base+"/") {
			relClean = filepath.ToSlash(filepath.Clean(filepath.Join(base, relClean)))
		}
		rel = relClean
	}

	// Ensure the path is inside MEDIA_ROOT and exists.
	abs, err := safeJoinAndCheck(a.cfg.MediaRoot, rel)
	if err != nil {
		a.redirectToAdmin(w, r, "", "")
		return
	}
	fi, err := os.Stat(abs)
	if err != nil || fi.IsDir() {
		a.redirectToAdmin(w, r, "", "")
		return
	}

	maxDownloads := parseInt64Default(r.FormValue("max_downloads"), 1)
	if maxDownloads < 0 {
		maxDownloads = 1
	}
	maxPerIP := parseOptionalInt64(r.FormValue("max_per_ip"))
	expiry := strings.TrimSpace(r.FormValue("expires_at"))
	var expiresAt sql.NullString
	if expiry != "" {
		// Accept RFC3339 or HTML datetime-local (interpreted in local timezone).
		if t, ok := parseUserTime(expiry); ok {
			expiresAt = sql.NullString{String: t.UTC().Format(time.RFC3339), Valid: true}
		}
	}

	uid, ok := r.Context().Value(ctxKeyUserID{}).(int64)
	if !ok {
		a.redirectToAdmin(w, r, "", "")
		return
	}

	shareSlug, err := a.getOrCreateShare(r.Context(), rel, uid)
	if err != nil {
		log.Printf("CREATE ERROR: getOrCreateShare failed: %v", err)
		a.redirectToAdmin(w, r, "", "")
		return
	}

	linkToken, err := randomToken(24)
	if err != nil {
		log.Printf("CREATE ERROR: randomToken failed: %v", err)
		a.redirectToAdmin(w, r, "", "")
		return
	}

	shareID, err := a.repo.GetShareIDBySlug(r.Context(), shareSlug)
	if err != nil {
		log.Printf("CREATE ERROR: GetShareIDBySlug failed: %v", err)
		a.redirectToAdmin(w, r, "", "")
		return
	}

	var exp *string
	if expiresAt.Valid {
		exp = &expiresAt.String
	}
	// maxPerIP is already *int64
	if err := a.repo.CreateLink(r.Context(), shareID, sha256Hex(linkToken), maxDownloads, exp, maxPerIP); err != nil {
		log.Printf("CREATE ERROR: CreateLink failed: %v", err)
		a.redirectToAdmin(w, r, "", "")
		return
	}

	// Redirect back with the link in query for easy copying.
	dl := fmt.Sprintf("%s/%s/%s", getBaseURL(r, a.cfg.PublicBase), shareSlug, linkToken)
	http.Redirect(w, r, a.cfg.AdminPath+"/?tab=create&created="+url.QueryEscape(dl), http.StatusSeeOther)
}

func getBaseURL(r *http.Request, fallback string) string {
	// Only trust X-Forwarded headers from localhost (nginx proxy)
	var proto, host string
	clientIP := getClientIP(r)
	isTrusted := clientIP == "127.0.0.1" || clientIP == "::1" || strings.HasPrefix(clientIP, "172.") || strings.HasPrefix(clientIP, "10.")

	if isTrusted {
		proto = strings.TrimSpace(r.Header.Get("X-Forwarded-Proto"))
		host = strings.TrimSpace(r.Header.Get("X-Forwarded-Host"))
	}

	if proto == "" {
		if r.TLS != nil {
			proto = "https"
		} else {
			proto = "http"
		}
	}
	if host == "" {
		host = r.Host
	}
	if proto != "" && host != "" {
		return proto + "://" + host
	}
	return strings.TrimRight(fallback, "/")
}

func parseUserTime(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, true
	}
	// datetime-local (no timezone): YYYY-MM-DDTHH:MM or YYYY-MM-DDTHH:MM:SS
	for _, layout := range []string{"2006-01-02T15:04:05", "2006-01-02T15:04"} {
		if t, err := time.ParseInLocation(layout, s, time.Local); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

func (a *app) getOrCreateShare(ctx context.Context, relpath string, userID int64) (string, error) {
	relpath = filepath.ToSlash(filepath.Clean(relpath))
	relpath = strings.TrimPrefix(relpath, "/")
	slug, err := a.repo.GetShareSlugByPath(ctx, relpath)
	if err == nil {
		return slug, nil
	}
	slug, err = randomToken(16)
	if err != nil {
		return "", err
	}
	isUpload := false
	if a.cfg.UploadTargetDir != "" {
		if rel, err := filepath.Rel(a.cfg.MediaRoot, a.cfg.UploadTargetDir); err == nil {
			uploadRel := filepath.ToSlash(filepath.Clean(rel))
			uploadRel = strings.TrimPrefix(uploadRel, "/")
			if uploadRel != "" {
				isUpload = relpath == uploadRel || strings.HasPrefix(relpath, uploadRel+"/")
			}
		}
	}
	_, err = a.repo.CreateShare(ctx, slug, relpath, userID, isUpload)
	if err != nil {
		return "", err
	}
	return slug, nil
}

func parseInt64Default(s string, d int64) int64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return d
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return d
	}
	return v
}

func parseOptionalInt64(s string) *int64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return nil
	}
	return &v
}

// handleAdminUpload handles file uploads to the share directory using streaming.
// Files are first written to the temp directory (NVMe) and then moved/copied to
// the final destination (HDD share folder) to avoid keeping the HDD awake during
// slow uploads.
func (a *app) handleAdminUpload(w http.ResponseWriter, r *http.Request) {
	// Check if upload is enabled
	if a.cfg.UploadTargetDir == "" {
		jsonError(w, http.StatusForbidden, "disabled", "Upload is not enabled")
		return
	}

	// Limit upload size to 10GB
	r.Body = http.MaxBytesReader(w, r.Body, 10<<30)

	// Use MultipartReader for streaming - does NOT buffer the entire file in memory
	mr, err := r.MultipartReader()
	if err != nil {
		log.Printf("UPLOAD ERROR: MultipartReader failed: %v", err)
		jsonError(w, http.StatusBadRequest, "parse_error", "Invalid request")
		return
	}

	var filename string
	var targetSubDir string
	var written int64
	var relPath string
	var finalPath string
	var tempPath string
	var dst *os.File

	// Determine if we should use temp directory (NVMe) for staging
	useTempDir := a.cfg.UploadTempDir != ""

	// Process parts one at a time (streaming)
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Printf("UPLOAD ERROR: NextPart failed: %v", err)
			if dst != nil {
				_ = dst.Close()
				if tempPath != "" {
					_ = os.Remove(tempPath)
				}
			}
			jsonError(w, http.StatusBadRequest, "parse_error", "Error reading request")
			return
		}

		formName := part.FormName()

		// Handle the "dir" form field (subdirectory within share folder)
		if formName == "dir" {
			buf := make([]byte, 1024)
			n, _ := part.Read(buf)
			targetSubDir = strings.TrimSpace(string(buf[:n]))
			targetSubDir = strings.Trim(targetSubDir, "/")
			// Security: prevent path traversal
			targetSubDir = filepath.Clean(targetSubDir)
			if strings.HasPrefix(targetSubDir, "..") {
				targetSubDir = ""
			}
			_ = part.Close()
			continue
		}

		// Handle the file upload
		if formName == "file" {
			filename = filepath.Base(part.FileName())
			filename = sanitizeFilename(filename)
			if filename == "" || filename == "." || filename == ".." {
				_ = part.Close()
				jsonError(w, http.StatusBadRequest, "invalid_filename", "Invalid filename")
				return
			}

			// Final path is always within the configured upload target directory
			if targetSubDir != "" {
				finalPath = filepath.Join(a.cfg.UploadTargetDir, targetSubDir, filename)
			} else {
				finalPath = filepath.Join(a.cfg.UploadTargetDir, filename)
			}

			// Security: ensure path stays within upload target directory
			baseDir := filepath.Clean(a.cfg.UploadTargetDir)
			targetPath := filepath.Clean(finalPath)
			relCheck, err := filepath.Rel(baseDir, targetPath)
			if err != nil || relCheck == ".." || strings.HasPrefix(relCheck, ".."+string(filepath.Separator)) {
				_ = part.Close()
				jsonError(w, http.StatusBadRequest, "invalid_path", "Invalid target path")
				return
			}

			// Build relative path for the share link (relative to MediaRoot)
			relPath, _ = filepath.Rel(a.cfg.MediaRoot, finalPath)
			if relPath == "" {
				relPath = filepath.Join("media", "share", filename)
			}

			// Determine write path (temp or final)
			// Note: File existence is checked atomically via O_EXCL during file creation
			var writePath string
			if useTempDir {
				// Write to temp directory first (NVMe - fast, doesn't wake HDD)
				tempPath = filepath.Join(a.cfg.UploadTempDir, filename+".uploading")
				writePath = tempPath
			} else {
				// Write directly to final destination
				writePath = finalPath
				// Ensure parent directory exists
				parentDir := filepath.Dir(finalPath)
				if err := os.MkdirAll(parentDir, 0750); err != nil {
					_ = part.Close()
					jsonError(w, http.StatusInternalServerError, "mkdir_error", "Could not create directory")
					return
				}
			}

			// Create destination file with O_EXCL to prevent race condition
			// O_EXCL ensures atomic "check and create" - fails if file exists
			dst, err = os.OpenFile(writePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
			if err != nil {
				_ = part.Close()
				if os.IsExist(err) {
					jsonError(w, http.StatusConflict, "exists", "File already exists")
				} else {
					jsonError(w, http.StatusInternalServerError, "create_error", "Could not create file")
				}
				return
			}

			// Stream directly from request to file (32KB buffer, constant memory usage)
			written, err = io.Copy(dst, part)
			_ = dst.Close()
			_ = part.Close()

			if err != nil {
				_ = os.Remove(writePath)
				jsonError(w, http.StatusInternalServerError, "write_error", "Error writing file")
				return
			}
		} else {
			_ = part.Close()
		}
	}

	if filename == "" {
		jsonError(w, http.StatusBadRequest, "no_file", "No file selected")
		return
	}

	// If we used temp directory, now copy to final destination (HDD)
	if useTempDir && tempPath != "" {
		// Ensure parent directory exists on final destination
		parentDir := filepath.Dir(finalPath)
		if err := os.MkdirAll(parentDir, 0750); err != nil {
			_ = os.Remove(tempPath)
			jsonError(w, http.StatusInternalServerError, "mkdir_error", "Could not create target directory")
			return
		}

		// Try rename first (fast if same filesystem, won't work across filesystems)
		if err := os.Rename(tempPath, finalPath); err != nil {
			// Rename failed (different filesystems), do a copy instead
			if err := copyFile(tempPath, finalPath); err != nil {
				// Cleanup temp file
				_ = os.Remove(tempPath)
				// Check if file already exists at destination
				if os.IsExist(err) {
					jsonError(w, http.StatusConflict, "exists", "File already exists")
				} else {
					jsonError(w, http.StatusInternalServerError, "copy_error", "Could not copy file to target directory")
				}
				return
			}
			// Remove temp file after successful copy
			_ = os.Remove(tempPath)
		}
		log.Printf("Uploaded file: %s (%d bytes) [staged via temp]", relPath, written)
	} else {
		log.Printf("Uploaded file: %s (%d bytes)", relPath, written)
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if err := json.NewEncoder(w).Encode(map[string]any{
		"success": true,
		"relpath": relPath,
		"size":    written,
	}); err != nil {
		log.Printf("json encode error: %v", err)
	}
}

// sanitizeFilename removes unsafe characters from a filename
func sanitizeFilename(name string) string {
	// Replace path separators and null bytes
	name = strings.ReplaceAll(name, "/", "_")
	name = strings.ReplaceAll(name, "\\", "_")
	name = strings.ReplaceAll(name, "\x00", "")

	// Remove leading dots to prevent hidden files
	name = strings.TrimLeft(name, ".")

	// Limit length
	if len(name) > 255 {
		ext := filepath.Ext(name)
		base := strings.TrimSuffix(name, ext)
		if len(ext) > 50 {
			ext = ext[:50]
		}
		name = base[:255-len(ext)] + ext
	}

	return name
}

// copyFile copies a file from src to dst using streaming (constant memory usage)
// Uses O_EXCL to prevent overwriting existing files (race condition safety)
func copyFile(src, dst string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = srcFile.Close() }()

	// O_EXCL ensures we don't overwrite an existing file
	dstFile, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer func() { _ = dstFile.Close() }()

	if _, err := io.Copy(dstFile, srcFile); err != nil {
		_ = os.Remove(dst) // Clean up partial file
		return err
	}

	return dstFile.Sync() // Ensure data is written to disk
}
