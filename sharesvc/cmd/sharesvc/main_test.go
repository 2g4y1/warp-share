package main

import (
	"errors"
	"html/template"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestCleanupTempDir(t *testing.T) {
	tmpDir := t.TempDir()

	// Create file and subdir
	filePath := filepath.Join(tmpDir, "temp.txt")
	subDir := filepath.Join(tmpDir, "sub")
	if err := os.WriteFile(filePath, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(subDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(subDir, "nested.txt"), []byte("y"), 0644); err != nil {
		t.Fatal(err)
	}

	cleanupTempDir(tmpDir)

	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("expected temp dir to be empty, got %d entries", len(entries))
	}
}

func TestCleanupTempDirMissingAndFile(t *testing.T) {
	// Missing dir should be ignored
	missing := filepath.Join(t.TempDir(), "missing")
	cleanupTempDir(missing)

	// File path should not panic and should remain
	filePath := filepath.Join(t.TempDir(), "temp.txt")
	if err := os.WriteFile(filePath, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	cleanupTempDir(filePath)
	if _, err := os.Stat(filePath); err != nil {
		t.Fatalf("expected file to remain, err=%v", err)
	}
}

func TestRenderTemplateError(t *testing.T) {
	a := newTestApp(t)
	tmpl := template.Must(template.New("err").Funcs(template.FuncMap{
		"err": func() (string, error) { return "", errors.New("boom") },
	}).Parse("{{err}}"))

	rr := httptest.NewRecorder()
	a.render(rr, tmpl, nil)
	if rr.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusInternalServerError)
	}
}

func TestMainFunction(t *testing.T) {
	shutdownChan = make(chan struct{})

	oldNotify := signalNotify
	oldStop := signalStop
	oldMake := makeSignalChan
	defer func() {
		signalNotify = oldNotify
		signalStop = oldStop
		makeSignalChan = oldMake
	}()

	sigChan := make(chan os.Signal, 1)
	makeSignalChan = func() chan os.Signal { return sigChan }
	signalNotify = func(c chan<- os.Signal, sig ...os.Signal) {}
	signalStop = func(c chan<- os.Signal) {}

	// Setup env for main()
	dataDir := t.TempDir()
	mediaRoot := t.TempDir()
	if err := os.MkdirAll(mediaRoot, 0755); err != nil {
		t.Fatal(err)
	}

	oldPublic := os.Getenv("PUBLIC_BASE")
	oldData := os.Getenv("DATA_DIR")
	oldMedia := os.Getenv("MEDIA_ROOT")
	oldAdmin := os.Getenv("ADMIN_PATH")
	oldListen := os.Getenv("LISTEN_ADDR")
	defer func() {
		_ = os.Setenv("PUBLIC_BASE", oldPublic)
		_ = os.Setenv("DATA_DIR", oldData)
		_ = os.Setenv("MEDIA_ROOT", oldMedia)
		_ = os.Setenv("ADMIN_PATH", oldAdmin)
		_ = os.Setenv("LISTEN_ADDR", oldListen)
	}()

	_ = os.Setenv("PUBLIC_BASE", "https://example.com")
	_ = os.Setenv("DATA_DIR", dataDir)
	_ = os.Setenv("MEDIA_ROOT", mediaRoot)
	_ = os.Setenv("ADMIN_PATH", "/test-admin")
	_ = os.Setenv("LISTEN_ADDR", "127.0.0.1:0")

	done := make(chan struct{})
	go func() {
		main()
		close(done)
	}()

	// Give server time to start, then signal shutdown
	time.Sleep(100 * time.Millisecond)
	sigChan <- syscall.SIGTERM

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("main did not shut down")
	}
}
