package main

import (
	"database/sql"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

func setupAdminDB(t *testing.T) (string, *sql.DB) {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "warp-share.sqlite")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	schema := `
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  created_at TEXT NOT NULL,
  must_change_password INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS sessions (
  id INTEGER PRIMARY KEY,
  token_hash TEXT NOT NULL UNIQUE,
  user_id INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL
);
`
	if _, err := db.Exec(schema); err != nil {
			_ = db.Close()
		t.Fatalf("init schema: %v", err)
	}
	return dbPath, db
}

func captureOutput(t *testing.T, fn func()) (string, string) {
	t.Helper()
	oldOut, oldErr := os.Stdout, os.Stderr
	rOut, wOut, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe stdout: %v", err)
	}
	rErr, wErr, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe stderr: %v", err)
	}
	os.Stdout, os.Stderr = wOut, wErr

	outCh := make(chan string, 1)
	errCh := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(rOut)
		outCh <- string(b)
	}()
	go func() {
		b, _ := io.ReadAll(rErr)
		errCh <- string(b)
	}()

	fn()
	_ = wOut.Close()
	_ = wErr.Close()
	os.Stdout, os.Stderr = oldOut, oldErr
	return <-outCh, <-errCh
}

func TestRandomPasswordFormat(t *testing.T) {
	pw := randomPassword()
	if len(pw) != 24 {
		t.Fatalf("len = %d, want 24", len(pw))
	}
	if strings.Contains(pw, "=") {
		t.Fatalf("password contains padding: %q", pw)
	}
	if !regexp.MustCompile(`^[A-Za-z0-9_-]+$`).MatchString(pw) {
		t.Fatalf("password not base64url: %q", pw)
	}
}

func TestResetPasswordSuccess(t *testing.T) {
	dbPath, db := setupAdminDB(t)
	defer func() { _ = db.Close() }()

	hash, err := bcrypt.GenerateFromPassword([]byte("oldpassword123"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	created := time.Now().UTC().Format(time.RFC3339)
	_, err = db.Exec("INSERT INTO users(id, username, password_hash, created_at) VALUES(1, 'admin', ?, ?)", string(hash), created)
	if err != nil {
		t.Fatalf("insert user: %v", err)
	}
	_, err = db.Exec("INSERT INTO sessions(token_hash, user_id, created_at, expires_at) VALUES('t1', 1, ?, ?), ('t2', 1, ?, ?)", created, created, created, created)
	if err != nil {
		t.Fatalf("insert sessions: %v", err)
	}

	out, _ := captureOutput(t, func() {
		if err := resetPassword(dbPath, t.TempDir(), "admin"); err != nil {
			t.Fatalf("resetPassword: %v", err)
		}
	})

	if !strings.Contains(out, "Password for 'admin' has been reset") {
		t.Fatalf("unexpected output: %q", out)
	}

	// Updated regex to match new format: "New password (from /path/file): password"
	passRe := regexp.MustCompile(`New password \(from [^)]+\): (.+)`)
	m := passRe.FindStringSubmatch(out)
	if len(m) != 2 {
		t.Fatalf("missing password in output: %q", out)
	}
	newPass := strings.TrimSpace(m[1])

	var storedHash string
	if err := db.QueryRow("SELECT password_hash FROM users WHERE id = 1").Scan(&storedHash); err != nil {
		t.Fatalf("read password hash: %v", err)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(newPass)); err != nil {
		t.Fatalf("password not updated: %v", err)
	}

	var sessions int
	if err := db.QueryRow("SELECT COUNT(1) FROM sessions WHERE user_id = 1").Scan(&sessions); err != nil {
		t.Fatalf("count sessions: %v", err)
	}
	if sessions != 0 {
		t.Fatalf("sessions = %d, want 0", sessions)
	}
}

func TestResetPasswordUserNotFound(t *testing.T) {
	dbPath, db := setupAdminDB(t)
	defer func() { _ = db.Close() }()

	if err := resetPassword(dbPath, t.TempDir(), "missing"); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("expected not found error, got %v", err)
	}
}

func TestListUsers(t *testing.T) {
	dbPath, db := setupAdminDB(t)
	defer func() { _ = db.Close() }()

	out, _ := captureOutput(t, func() {
		if err := listUsers(dbPath); err != nil {
			t.Fatalf("listUsers: %v", err)
		}
	})
	if !strings.Contains(out, "(no users)") {
		t.Fatalf("expected no users output, got %q", out)
	}

	created := time.Now().UTC().Format(time.RFC3339)
	_, err := db.Exec("INSERT INTO users(id, username, password_hash, created_at) VALUES(1, 'admin', 'hash', ?), (2, 'alice', 'hash', ?)", created, created)
	if err != nil {
		t.Fatalf("insert users: %v", err)
	}

	out2, _ := captureOutput(t, func() {
		if err := listUsers(dbPath); err != nil {
			t.Fatalf("listUsers: %v", err)
		}
	})
	if !strings.Contains(out2, "Username") || !strings.Contains(out2, "admin") || !strings.Contains(out2, "alice") {
		t.Fatalf("unexpected list output: %q", out2)
	}
}
