package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestHandleDownload(t *testing.T) {
	a := newTestApp(t)
	ctx := context.Background()

	// Create user
	_, err := a.repo.db.Exec("INSERT INTO users(id, username, password_hash, created_at) VALUES(1, 'admin', 'hash', ?)", nowRFC3339())
	if err != nil {
		t.Fatal(err)
	}

	// Create file
	relPath := "media/file.txt"
	absPath := filepath.Join(a.cfg.MediaRoot, relPath)
	if err := os.MkdirAll(filepath.Dir(absPath), 0755); err != nil {
		t.Fatal(err)
	}
	content := []byte("hello world")
	if err := os.WriteFile(absPath, content, 0644); err != nil {
		t.Fatal(err)
	}

	// Create share + link
	shareSlug := "abcdefghijkl"
	shareID, err := a.repo.CreateShare(ctx, shareSlug, relPath, 1, false)
	if err != nil {
		t.Fatal(err)
	}
	token := "tokenabcdefghijklmnopqrstuv"
	if err := a.repo.CreateLink(ctx, shareID, sha256Hex(token), 5, nil, nil); err != nil {
		t.Fatal(err)
	}

	t.Run("invalid method", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		rr := httptest.NewRecorder()
		a.handleDownload(rr, req, shareSlug, token)
		if rr.Code != http.StatusNotFound {
			t.Errorf("status = %d, want %d", rr.Code, http.StatusNotFound)
		}
	})

	t.Run("GET download", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rr := httptest.NewRecorder()
		a.handleDownload(rr, req, shareSlug, token)
		if rr.Code != http.StatusOK {
			t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
		}
		if !strings.Contains(rr.Header().Get("Content-Disposition"), "file.txt") {
			t.Errorf("Content-Disposition = %q", rr.Header().Get("Content-Disposition"))
		}
		if rr.Body.String() != string(content) {
			t.Errorf("body = %q, want %q", rr.Body.String(), string(content))
		}
	})

	t.Run("HEAD download", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodHead, "/", nil)
		rr := httptest.NewRecorder()
		a.handleDownload(rr, req, shareSlug, token)
		if rr.Code != http.StatusOK {
			t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
		}
		if rr.Body.Len() != 0 {
			t.Errorf("body length = %d, want 0", rr.Body.Len())
		}
	})
}

func TestHandleLanding(t *testing.T) {
	a := newTestApp(t)
	ctx := context.Background()

	_, err := a.repo.db.Exec("INSERT INTO users(id, username, password_hash, created_at) VALUES(1, 'admin', 'hash', ?)", nowRFC3339())
	if err != nil {
		t.Fatal(err)
	}

	relPath := "media/landing.txt"
	absPath := filepath.Join(a.cfg.MediaRoot, relPath)
	if err := os.MkdirAll(filepath.Dir(absPath), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(absPath, []byte("ok"), 0644); err != nil {
		t.Fatal(err)
	}

	shareSlug := "mnopqrstvwxz"
	shareID, err := a.repo.CreateShare(ctx, shareSlug, relPath, 1, false)
	if err != nil {
		t.Fatal(err)
	}
	token := "tokentokentokentokentk"
	if err := a.repo.CreateLink(ctx, shareID, sha256Hex(token), 2, nil, nil); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	a.handleLanding(rr, req, shareSlug, token)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	if !strings.Contains(rr.Body.String(), "landing.txt") {
		t.Errorf("body does not contain filename")
	}
}

func TestCountingWriter(t *testing.T) {
	rr := httptest.NewRecorder()
	cw := &countingWriter{ResponseWriter: rr}

	_, _ = cw.Write([]byte("abc"))
	if cw.written != 3 {
		t.Errorf("written = %d, want 3", cw.written)
	}

	cw.Flush()
	if cw.Unwrap() != rr {
		t.Error("Unwrap should return underlying ResponseWriter")
	}

	// Ensure write still works after time advance
	_, _ = cw.Write([]byte("d"))
	if cw.written != 4 {
		t.Errorf("written = %d, want 4", cw.written)
	}
}

func TestHandleDownloadHonorsGrantTTL(t *testing.T) {
	a := newTestApp(t)
	ctx := context.Background()

	_, err := a.repo.db.Exec("INSERT INTO users(id, username, password_hash, created_at) VALUES(1, 'admin', 'hash', ?)", nowRFC3339())
	if err != nil {
		t.Fatal(err)
	}

	relPath := "media/grant.txt"
	absPath := filepath.Join(a.cfg.MediaRoot, relPath)
	if err := os.MkdirAll(filepath.Dir(absPath), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(absPath, []byte("ok"), 0644); err != nil {
		t.Fatal(err)
	}

	shareSlug := "abcdefghijkl"
	shareID, err := a.repo.CreateShare(ctx, shareSlug, relPath, 1, false)
	if err != nil {
		t.Fatal(err)
	}
	token := "abcdefghijklmnopqrstuvwx"
	if err := a.repo.CreateLink(ctx, shareID, sha256Hex(token), 1, nil, nil); err != nil {
		t.Fatal(err)
	}

	// Prime link usage to create active grant
	now := time.Now().UTC()
	_, _ = a.repo.ConsumeLink(ctx, shareSlug, sha256Hex(token), "127.0.0.1", now, time.Hour)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	rr := httptest.NewRecorder()
	a.handleDownload(rr, req, shareSlug, token)
	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}
}

func TestHandleDownloadNotFoundCases(t *testing.T) {
	a := newTestApp(t)
	ctx := context.Background()

	_, err := a.repo.db.Exec("INSERT INTO users(id, username, password_hash, created_at) VALUES(1, 'admin', 'hash', ?)", nowRFC3339())
	if err != nil {
		t.Fatal(err)
	}

	// link points to missing file
	shareSlug := "missingfile12"
	shareID, _ := a.repo.CreateShare(ctx, shareSlug, "media/missing.txt", 1, false)
	token := "tokmissingfilemissingf"
	_ = a.repo.CreateLink(ctx, shareID, sha256Hex(token), 1, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	a.handleDownload(rr, req, shareSlug, token)
	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusNotFound)
	}

	// invalid path traversal
	shareSlug2 := "badpathslug1"
	shareID2, _ := a.repo.CreateShare(ctx, shareSlug2, "../etc/passwd", 1, false)
	token2 := "tokbadpathbadpathbad"
	_ = a.repo.CreateLink(ctx, shareID2, sha256Hex(token2), 1, nil, nil)

	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	rr2 := httptest.NewRecorder()
	a.handleDownload(rr2, req2, shareSlug2, token2)
	if rr2.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rr2.Code, http.StatusNotFound)
	}
}
