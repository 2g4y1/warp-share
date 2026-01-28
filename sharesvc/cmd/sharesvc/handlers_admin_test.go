package main

import (
	"bytes"
	"context"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func TestRedirectToAdmin(t *testing.T) {
	a := newTestApp(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()

	a.redirectToAdmin(rr, req, "settings", "ok")
	loc := rr.Header().Get("Location")
	if !strings.Contains(loc, "tab=settings") || !strings.Contains(loc, "msg=ok") {
		t.Errorf("Location = %q, want tab and msg", loc)
	}
}

func TestHandleAdminSpeedLimit(t *testing.T) {
	a := newTestApp(t)

	// invalid values
	form := url.Values{"default_limit": {"-1"}, "alt_limit": {"1"}, "alt_start": {"0"}, "alt_end": {"1"}}
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	a.handleAdminSpeedLimit(rr, req)
	if rr.Code != http.StatusSeeOther {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusSeeOther)
	}

	// valid values
	form2 := url.Values{"default_limit": {"300"}, "alt_limit": {"100"}, "alt_start": {"1"}, "alt_end": {"7"}}
	req2 := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form2.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr2 := httptest.NewRecorder()
	a.handleAdminSpeedLimit(rr2, req2)

	if rr2.Code != http.StatusSeeOther {
		t.Errorf("status = %d, want %d", rr2.Code, http.StatusSeeOther)
	}
	def, alt, start, end := a.sl.GetConfig()
	if def != 300 || alt != 100 || start != 1 || end != 7 {
		t.Errorf("limits = %d,%d,%d,%d", def, alt, start, end)
	}
	if _, err := os.Stat(filepath.Join(a.cfg.DataDir, "speed_limit.txt")); err != nil {
		t.Errorf("expected speed_limit.txt to exist: %v", err)
	}
}

func TestHandleAdminQuickCreate(t *testing.T) {
	a := newTestApp(t)
	ctx := context.Background()

	// invalid CSRF
	form := url.Values{"slug": {"abcdefghijkl"}}
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	a.handleAdminQuickCreate(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusForbidden)
	}

	// invalid slug
	sessionToken := "csrf-token"
	csrf := generateCSRFToken(sessionToken)
	form2 := url.Values{"slug": {"bad"}, "_csrf": {csrf}}
	req2 := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form2.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req2.AddCookie(&http.Cookie{Name: "warp_admin", Value: sessionToken})
	rr2 := httptest.NewRecorder()
	a.handleAdminQuickCreate(rr2, req2)
	if rr2.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rr2.Code, http.StatusBadRequest)
	}

	// share not found
	form3 := url.Values{"slug": {"abcdefghijkl"}, "_csrf": {csrf}}
	req3 := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form3.Encode()))
	req3.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req3.AddCookie(&http.Cookie{Name: "warp_admin", Value: sessionToken})
	rr3 := httptest.NewRecorder()
	a.handleAdminQuickCreate(rr3, req3)
	if rr3.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rr3.Code, http.StatusNotFound)
	}

	// success
	_, err := a.repo.db.Exec("INSERT INTO users(id, username, password_hash, created_at) VALUES(1, 'admin', 'hash', ?)", nowRFC3339())
	if err != nil {
		t.Fatal(err)
	}
	_, err = a.repo.CreateShare(ctx, "abcdefghijkl", "media/file.txt", 1, false)
	if err != nil {
		t.Fatal(err)
	}
	form4 := url.Values{"slug": {"abcdefghijkl"}, "_csrf": {csrf}}
	req4 := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form4.Encode()))
	req4.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req4.AddCookie(&http.Cookie{Name: "warp_admin", Value: sessionToken})
	rr4 := httptest.NewRecorder()
	a.handleAdminQuickCreate(rr4, req4)
	if rr4.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr4.Code, http.StatusOK)
	}
	var payload map[string]string
	if err := json.Unmarshal(rr4.Body.Bytes(), &payload); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	if payload["url"] == "" {
		t.Error("expected url in response")
	}
}

func TestHandleAdminHome(t *testing.T) {
	a := newTestApp(t)
	ctx := context.Background()

	_, err := a.repo.db.Exec("INSERT INTO users(id, username, password_hash, created_at) VALUES(1, 'admin', 'hash', ?)", nowRFC3339())
	if err != nil {
		t.Fatal(err)
	}
	shareID, _ := a.repo.CreateShare(ctx, "homeslug1234", "media/home.txt", 1, false)
	_ = a.repo.CreateLink(ctx, shareID, sha256Hex("home"), 1, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/?tab=stats", nil)
	req = req.WithContext(context.WithValue(ctx, ctxKeyUserID{}, int64(1)))
	rr := httptest.NewRecorder()

	a.handleAdminHome(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}
}

func TestHandleAdminStaticAssets(t *testing.T) {
	a := newTestApp(t)

	cases := []struct {
		name    string
		handler func(http.ResponseWriter, *http.Request)
	}{
		{"admin.css", a.handleAdminStaticCSS},
		{"base.css", a.handleAdminStaticBaseCSS},
		{"browse.css", a.handleAdminStaticBrowseCSS},
		{"login.css", a.handleAdminStaticLoginCSS},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			rr := httptest.NewRecorder()
			c.handler(rr, req)
			if rr.Code != http.StatusOK {
				t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
			}
			if ct := rr.Header().Get("Content-Type"); ct != "text/css; charset=utf-8" {
				t.Errorf("Content-Type = %q, want CSS", ct)
			}
		})
	}
}

func TestHandleAdminChangePassword(t *testing.T) {
	a := newTestApp(t)
	ctx := context.WithValue(context.Background(), ctxKeyUserID{}, int64(1))

	hash, err := bcrypt.GenerateFromPassword([]byte("oldpassword123"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}
	_, err = a.repo.db.Exec("INSERT INTO users(id, username, password_hash, created_at) VALUES(1, 'admin', ?, ?)", string(hash), nowRFC3339())
	if err != nil {
		t.Fatal(err)
	}

	form := url.Values{
		"current_password": {"oldpassword123"},
		"new_username":     {"newuser"},
		"new_password":     {"newpassword123"},
		"new_password2":    {"newpassword123"},
	}
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = req.WithContext(ctx)
	rr := httptest.NewRecorder()

	a.handleAdminChangePassword(rr, req)
	if rr.Code != http.StatusSeeOther {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusSeeOther)
	}

	uname, err := a.repo.GetUsernameByID(context.Background(), 1)
	if err != nil || uname != "newuser" {
		t.Errorf("username = %q, err=%v", uname, err)
	}

	if _, err := a.repo.AuthenticateUser(context.Background(), "newuser", "newpassword123"); err != nil {
		t.Errorf("AuthenticateUser failed after password change: %v", err)
	}
}

func TestGetLinks(t *testing.T) {
	a := newTestApp(t)
	ctx := context.Background()

	_, err := a.repo.db.Exec("INSERT INTO users(id, username, password_hash, created_at) VALUES(1, 'admin', 'hash', ?)", nowRFC3339())
	if err != nil {
		t.Fatal(err)
	}

	shareID, err := a.repo.CreateShare(ctx, "share1234567", "media/file1.txt", 1, false)
	if err != nil {
		t.Fatal(err)
	}

	// valid link
	if err := a.repo.CreateLink(ctx, shareID, sha256Hex("token1"), 5, nil, nil); err != nil {
		t.Fatal(err)
	}

	// disabled link
	if err := a.repo.CreateLink(ctx, shareID, sha256Hex("token2"), 5, nil, nil); err != nil {
		t.Fatal(err)
	}
	_, _ = a.repo.db.Exec("UPDATE links SET disabled = 1 WHERE token_hash = ?", sha256Hex("token2"))

	// expired link
	exp := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	if err := a.repo.CreateLink(ctx, shareID, sha256Hex("token3"), 5, &exp, nil); err != nil {
		t.Fatal(err)
	}

	links, err := a.getLinks(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(links) < 3 {
		t.Fatalf("expected at least 3 links, got %d", len(links))
	}

	statusCount := map[string]int{}
	for _, l := range links {
		statusCount[l.Status]++
	}
	if statusCount["valid"] == 0 || statusCount["disabled"] == 0 || statusCount["expired"] == 0 {
		t.Errorf("status counts = %#v", statusCount)
	}
}

func TestHandleAdminDisableDeleteCleanup(t *testing.T) {
	a := newTestApp(t)
	ctx := context.Background()

	_, err := a.repo.db.Exec("INSERT INTO users(id, username, password_hash, created_at) VALUES(1, 'admin', 'hash', ?)", nowRFC3339())
	if err != nil {
		t.Fatal(err)
	}

	shareID, err := a.repo.CreateShare(ctx, "share1234567", "media/file1.txt", 1, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.repo.CreateLink(ctx, shareID, sha256Hex("token1"), 1, nil, nil); err != nil {
		t.Fatal(err)
	}

	var linkID int64
	_ = a.repo.db.QueryRow("SELECT id FROM links WHERE token_hash = ?", sha256Hex("token1")).Scan(&linkID)

	// disable
	form := url.Values{"id": {strconv.FormatInt(linkID, 10)}}
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	a.handleAdminDisableLink(rr, req)
	if rr.Code != http.StatusSeeOther {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusSeeOther)
	}

	// delete
	req2 := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr2 := httptest.NewRecorder()
	a.handleAdminDeleteLink(rr2, req2)
	if rr2.Code != http.StatusSeeOther {
		t.Errorf("status = %d, want %d", rr2.Code, http.StatusSeeOther)
	}

	// cleanup
	// create inactive link and orphaned share
	exp := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	_ = a.repo.CreateLink(ctx, shareID, sha256Hex("token2"), 1, &exp, nil)
	_, _ = a.repo.CreateShare(ctx, "orphanshare12", "media/orphan.txt", 1, false)

	req3 := httptest.NewRequest(http.MethodPost, "/", nil)
	rr3 := httptest.NewRecorder()
	a.handleAdminCleanupLinks(rr3, req3)
	if rr3.Code != http.StatusSeeOther {
		t.Errorf("status = %d, want %d", rr3.Code, http.StatusSeeOther)
	}
}

func TestHandleAdminBrowseCreateUploadAndCopy(t *testing.T) {
	a := newTestApp(t)
	ctx := context.Background()

	// setup media files
	baseDir := filepath.Join(a.cfg.MediaRoot, "media")
	if err := os.MkdirAll(baseDir, 0755); err != nil {
		t.Fatal(err)
	}
	filePath := filepath.Join(baseDir, "file.txt")
	if err := os.WriteFile(filePath, []byte("ok"), 0644); err != nil {
		t.Fatal(err)
	}

	// browse
	req := httptest.NewRequest(http.MethodGet, "/?dir=media", nil)
	rr := httptest.NewRecorder()
	a.handleAdminBrowse(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	if !strings.Contains(rr.Body.String(), "file.txt") {
		t.Error("browse output should contain file name")
	}

	// create link
	_, err := a.repo.db.Exec("INSERT INTO users(id, username, password_hash, created_at) VALUES(1, 'admin', 'hash', ?)", nowRFC3339())
	if err != nil {
		t.Fatal(err)
	}
	form := url.Values{"relpath": {"media/file.txt"}, "max_downloads": {"1"}}
	req2 := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req2 = req2.WithContext(context.WithValue(ctx, ctxKeyUserID{}, int64(1)))
	rr2 := httptest.NewRecorder()
	a.handleAdminCreate(rr2, req2)
	if rr2.Code != http.StatusSeeOther {
		t.Errorf("status = %d, want %d", rr2.Code, http.StatusSeeOther)
	}
	if !strings.Contains(rr2.Header().Get("Location"), "created=") {
		t.Errorf("expected created link redirect, got %q", rr2.Header().Get("Location"))
	}

	// upload disabled
	a.cfg.UploadTargetDir = ""
	req3 := httptest.NewRequest(http.MethodPost, "/", nil)
	rr3 := httptest.NewRecorder()
	a.handleAdminUpload(rr3, req3)
	if rr3.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rr3.Code, http.StatusForbidden)
	}

	// copyFile
	src := filepath.Join(a.cfg.MediaRoot, "src.txt")
	dst := filepath.Join(a.cfg.MediaRoot, "dst.txt")
	if err := os.WriteFile(src, []byte("copy"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := copyFile(src, dst); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(dst)
	if string(data) != "copy" {
		t.Errorf("copied data = %q, want %q", string(data), "copy")
	}
}

func TestGetOrCreateShare(t *testing.T) {
	a := newTestApp(t)
	ctx := context.Background()

	_, err := a.repo.db.Exec("INSERT INTO users(id, username, password_hash, created_at) VALUES(1, 'admin', 'hash', ?)", nowRFC3339())
	if err != nil {
		t.Fatal(err)
	}

	// Create once
	slug, err := a.getOrCreateShare(ctx, "media/file.txt", 1)
	if err != nil {
		t.Fatal(err)
	}
	// Should return same slug
	slug2, err := a.getOrCreateShare(ctx, "media/file.txt", 1)
	if err != nil {
		t.Fatal(err)
	}
	if slug != slug2 {
		t.Errorf("slug = %q, want %q", slug2, slug)
	}

	// Upload detection
	a.cfg.UploadTargetDir = filepath.Join(a.cfg.MediaRoot, "uploads")
	slug3, err := a.getOrCreateShare(ctx, "uploads/file.txt", 1)
	if err != nil {
		t.Fatal(err)
	}
	var isUpload int
	_ = a.repo.db.QueryRow("SELECT is_upload FROM shares WHERE slug = ?", slug3).Scan(&isUpload)
	if isUpload != 1 {
		t.Errorf("is_upload = %d, want 1", isUpload)
	}
}

func TestHandleAdminUploadSuccess(t *testing.T) {
	a := newTestApp(t)
	a.cfg.UploadTargetDir = filepath.Join(a.cfg.MediaRoot, "uploads")

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	_ = writer.WriteField("dir", "sub")
	part, err := writer.CreateFormFile("file", "test.txt")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = part.Write([]byte("hello"))
	_ = writer.Close()

	req := httptest.NewRequest(http.MethodPost, "/", &body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	rr := httptest.NewRecorder()

	a.handleAdminUpload(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	if !strings.Contains(rr.Body.String(), "\"success\":true") {
		t.Errorf("response = %q, want success", rr.Body.String())
	}
	// Ensure file exists in upload dir
	path := filepath.Join(a.cfg.UploadTargetDir, "sub", "test.txt")
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("uploaded file missing: %v", err)
	}
}

func TestHandleAdminUploadTempDirCopy(t *testing.T) {
	a := newTestApp(t)
	a.cfg.UploadTargetDir = filepath.Join(a.cfg.MediaRoot, "uploads")
	a.cfg.UploadTempDir = filepath.Join(a.cfg.DataDir, "tmp")
	if err := os.MkdirAll(a.cfg.UploadTempDir, 0755); err != nil {
		t.Fatal(err)
	}

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("file", "temp.txt")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = part.Write([]byte("tempdata"))
	_ = writer.Close()

	req := httptest.NewRequest(http.MethodPost, "/", &body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	rr := httptest.NewRecorder()

	a.handleAdminUpload(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	// Ensure file exists in final destination
	path := filepath.Join(a.cfg.UploadTargetDir, "temp.txt")
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("uploaded file missing: %v", err)
	}
}

func TestHandleAdminUploadErrors(t *testing.T) {
	a := newTestApp(t)
	a.cfg.UploadTargetDir = filepath.Join(a.cfg.MediaRoot, "uploads")

	// no file
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	_ = writer.Close()
	req := httptest.NewRequest(http.MethodPost, "/", &body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	rr := httptest.NewRecorder()
	a.handleAdminUpload(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}

	// invalid multipart
	reqBad := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("invalid"))
	reqBad.Header.Set("Content-Type", "multipart/form-data")
	rrBad := httptest.NewRecorder()
	a.handleAdminUpload(rrBad, reqBad)
	if rrBad.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rrBad.Code, http.StatusBadRequest)
	}

	// invalid filename
	var body2 bytes.Buffer
	writer2 := multipart.NewWriter(&body2)
	part, err := writer2.CreateFormFile("file", "..")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = part.Write([]byte("x"))
	_ = writer2.Close()
	req2 := httptest.NewRequest(http.MethodPost, "/", &body2)
	req2.Header.Set("Content-Type", writer2.FormDataContentType())
	rr2 := httptest.NewRecorder()
	a.handleAdminUpload(rr2, req2)
	if rr2.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rr2.Code, http.StatusBadRequest)
	}

	// file already exists
	if err := os.MkdirAll(a.cfg.UploadTargetDir, 0755); err != nil {
		t.Fatal(err)
	}
	existing := filepath.Join(a.cfg.UploadTargetDir, "dup.txt")
	if err := os.WriteFile(existing, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	var body3 bytes.Buffer
	writer3 := multipart.NewWriter(&body3)
	part3, err := writer3.CreateFormFile("file", "dup.txt")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = part3.Write([]byte("y"))
	_ = writer3.Close()
	req3 := httptest.NewRequest(http.MethodPost, "/", &body3)
	req3.Header.Set("Content-Type", writer3.FormDataContentType())
	rr3 := httptest.NewRecorder()
	a.handleAdminUpload(rr3, req3)
	if rr3.Code != http.StatusConflict {
		t.Errorf("status = %d, want %d", rr3.Code, http.StatusConflict)
	}
}

func TestHandleAdminChangePasswordErrors(t *testing.T) {
	a := newTestApp(t)
	ctx := context.WithValue(context.Background(), ctxKeyUserID{}, int64(1))

	hash, err := bcrypt.GenerateFromPassword([]byte("oldpassword123"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}
	_, err = a.repo.db.Exec("INSERT INTO users(id, username, password_hash, created_at) VALUES(1, 'admin', ?, ?)", string(hash), nowRFC3339())
	if err != nil {
		t.Fatal(err)
	}

	// missing current password
	form := url.Values{}
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = req.WithContext(ctx)
	rr := httptest.NewRecorder()
	a.handleAdminChangePassword(rr, req)
	if rr.Code != http.StatusSeeOther {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusSeeOther)
	}

	// wrong current password
	form2 := url.Values{"current_password": {"wrong"}}
	req2 := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form2.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req2 = req2.WithContext(ctx)
	rr2 := httptest.NewRecorder()
	a.handleAdminChangePassword(rr2, req2)
	if rr2.Code != http.StatusSeeOther {
		t.Errorf("status = %d, want %d", rr2.Code, http.StatusSeeOther)
	}

	// invalid username
	form3 := url.Values{"current_password": {"oldpassword123"}, "new_username": {"ab"}}
	req3 := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form3.Encode()))
	req3.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req3 = req3.WithContext(ctx)
	rr3 := httptest.NewRecorder()
	a.handleAdminChangePassword(rr3, req3)
	if rr3.Code != http.StatusSeeOther {
		t.Errorf("status = %d, want %d", rr3.Code, http.StatusSeeOther)
	}

	// password mismatch
	form4 := url.Values{"current_password": {"oldpassword123"}, "new_password": {"newpassword123"}, "new_password2": {"nope"}}
	req4 := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form4.Encode()))
	req4.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req4 = req4.WithContext(ctx)
	rr4 := httptest.NewRecorder()
	a.handleAdminChangePassword(rr4, req4)
	if rr4.Code != http.StatusSeeOther {
		t.Errorf("status = %d, want %d", rr4.Code, http.StatusSeeOther)
	}
}

func TestHandleAdminChangePasswordNoUser(t *testing.T) {
	a := newTestApp(t)
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	rr := httptest.NewRecorder()
	a.handleAdminChangePassword(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusNotFound)
	}
}

func TestHandleAdminCreateErrors(t *testing.T) {
	a := newTestApp(t)

	// missing relpath
	form := url.Values{}
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	a.handleAdminCreate(rr, req)
	if rr.Code != http.StatusSeeOther {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusSeeOther)
	}

	// invalid path
	form2 := url.Values{"relpath": {"../etc/passwd"}}
	req2 := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form2.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req2 = req2.WithContext(context.WithValue(context.Background(), ctxKeyUserID{}, int64(1)))
	rr2 := httptest.NewRecorder()
	a.handleAdminCreate(rr2, req2)
	if rr2.Code != http.StatusSeeOther {
		t.Errorf("status = %d, want %d", rr2.Code, http.StatusSeeOther)
	}

	// relpath is directory
	baseDir := filepath.Join(a.cfg.MediaRoot, "media")
	if err := os.MkdirAll(baseDir, 0755); err != nil {
		t.Fatal(err)
	}
	form3 := url.Values{"relpath": {"media"}}
	req3 := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form3.Encode()))
	req3.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req3 = req3.WithContext(context.WithValue(context.Background(), ctxKeyUserID{}, int64(1)))
	rr3 := httptest.NewRecorder()
	a.handleAdminCreate(rr3, req3)
	if rr3.Code != http.StatusSeeOther {
		t.Errorf("status = %d, want %d", rr3.Code, http.StatusSeeOther)
	}

	// missing user context
	filePath := filepath.Join(baseDir, "file.txt")
	if err := os.WriteFile(filePath, []byte("ok"), 0644); err != nil {
		t.Fatal(err)
	}
	form4 := url.Values{"relpath": {"media/file.txt"}}
	req4 := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form4.Encode()))
	req4.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr4 := httptest.NewRecorder()
	a.handleAdminCreate(rr4, req4)
	if rr4.Code != http.StatusSeeOther {
		t.Errorf("status = %d, want %d", rr4.Code, http.StatusSeeOther)
	}
}

func TestHandleAdminCreateWithExpiry(t *testing.T) {
	a := newTestApp(t)
	ctx := context.Background()

	// file exists
	baseDir := filepath.Join(a.cfg.MediaRoot, "media")
	if err := os.MkdirAll(baseDir, 0755); err != nil {
		t.Fatal(err)
	}
	filePath := filepath.Join(baseDir, "file.txt")
	if err := os.WriteFile(filePath, []byte("ok"), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := a.repo.db.Exec("INSERT INTO users(id, username, password_hash, created_at) VALUES(1, 'admin', 'hash', ?)", nowRFC3339())
	if err != nil {
		t.Fatal(err)
	}
	form := url.Values{
		"relpath":      {"media/file.txt"},
		"max_downloads": {"1"},
		"expires_at":   {"2025-01-01T10:00"},
	}
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = req.WithContext(context.WithValue(ctx, ctxKeyUserID{}, int64(1)))
	rr := httptest.NewRecorder()

	a.handleAdminCreate(rr, req)
	if rr.Code != http.StatusSeeOther {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusSeeOther)
	}
}

func TestHandleAdminBrowseErrors(t *testing.T) {
	a := newTestApp(t)
	a.cfg.BrowseStartRel = "media"

	// dir outside base
	req := httptest.NewRequest(http.MethodGet, "/?dir=other", nil)
	rr := httptest.NewRecorder()
	a.handleAdminBrowse(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusNotFound)
	}
}

func TestHandleAdminBrowseHiddenFiles(t *testing.T) {
	a := newTestApp(t)
	baseDir := filepath.Join(a.cfg.MediaRoot, "media")
	if err := os.MkdirAll(baseDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(baseDir, ".hidden"), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(baseDir, "visible.txt"), []byte("y"), 0644); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/?dir=media", nil)
	rr := httptest.NewRecorder()
	a.handleAdminBrowse(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	if strings.Contains(rr.Body.String(), ".hidden") {
		t.Error("hidden files should not be listed")
	}
	if !strings.Contains(rr.Body.String(), "visible.txt") {
		t.Error("visible file should be listed")
	}
}

func TestHandleAdminDisableDeleteInvalidID(t *testing.T) {
	a := newTestApp(t)

	form := url.Values{"id": {"0"}}
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	a.handleAdminDisableLink(rr, req)
	if rr.Code != http.StatusSeeOther {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusSeeOther)
	}

	req2 := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr2 := httptest.NewRecorder()
	a.handleAdminDeleteLink(rr2, req2)
	if rr2.Code != http.StatusSeeOther {
		t.Errorf("status = %d, want %d", rr2.Code, http.StatusSeeOther)
	}
}

func TestHandleAdminCleanupLinksFailure(t *testing.T) {
	a := newTestApp(t)
	_ = a.repo.db.Close()

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	rr := httptest.NewRecorder()
	a.handleAdminCleanupLinks(rr, req)

	if rr.Code != http.StatusSeeOther {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusSeeOther)
	}
	loc := rr.Header().Get("Location")
	if !strings.Contains(loc, "Cleanup+failed") && !strings.Contains(loc, "Cleanup%20failed") {
		t.Errorf("Location = %q, want cleanup failed message", loc)
	}
}

func TestHandleAdminBrowsePickModeParent(t *testing.T) {
	a := newTestApp(t)

	baseDir := filepath.Join(a.cfg.MediaRoot, "media", "sub")
	if err := os.MkdirAll(baseDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(baseDir, "file.txt"), []byte("ok"), 0644); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/?dir=media/sub&pick=1", nil)
	rr := httptest.NewRecorder()
	a.handleAdminBrowse(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "data-pick=\"1\"") {
		t.Errorf("expected pick mode in body")
	}
	if !strings.Contains(body, "data-rel=\"sub/file.txt\"") {
		t.Errorf("expected data-rel for file")
	}
	if !strings.Contains(body, "dir=media&pick=1") {
		t.Errorf("expected parent link")
	}
}

func TestHandleAdminBrowseBasePickRel(t *testing.T) {
	a := newTestApp(t)
	a.cfg.BrowseStartRel = "media/sub"

	baseDir := filepath.Join(a.cfg.MediaRoot, "media", "sub")
	if err := os.MkdirAll(baseDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(baseDir, "file.txt"), []byte("ok"), 0644); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/?dir=media/sub&pick=1", nil)
	rr := httptest.NewRecorder()
	a.handleAdminBrowse(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	body := rr.Body.String()
	if strings.Contains(body, "up one level") {
		t.Errorf("did not expect parent link for base dir")
	}
	if !strings.Contains(body, "data-rel=\"file.txt\"") {
		t.Errorf("expected base-relative pick rel")
	}
}

func TestHandleAdminHomeWithCSRFAndQR(t *testing.T) {
	a := newTestApp(t)
	ctx := context.WithValue(context.Background(), ctxKeyUserID{}, int64(1))

	_, err := a.repo.db.Exec("INSERT INTO users(id, username, password_hash, created_at) VALUES(1, 'admin', 'hash', ?)", nowRFC3339())
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/?created=https://example.com/x", nil)
	req = req.WithContext(ctx)
	req.AddCookie(&http.Cookie{Name: "warp_admin", Value: "session"})
	rr := httptest.NewRecorder()

	a.handleAdminHome(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}
}

func TestCopyFileErrors(t *testing.T) {
	a := newTestApp(t)
	src := filepath.Join(a.cfg.MediaRoot, "missing.txt")
	dst := filepath.Join(a.cfg.MediaRoot, "dst.txt")
	if err := copyFile(src, dst); err == nil {
		t.Error("expected error for missing src")
	}

	// dst exists
	if err := os.WriteFile(dst, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	src2 := filepath.Join(a.cfg.MediaRoot, "src.txt")
	if err := os.WriteFile(src2, []byte("y"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := copyFile(src2, dst); err == nil {
		t.Error("expected error for existing dst")
	}
}
