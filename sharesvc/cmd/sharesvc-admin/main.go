package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

const usage = `warp-admin - Admin tool for warp-share

Usage:
  warp-admin reset-password <username>   Reset password (generates random password)
  warp-admin list-users                  List all users
  warp-admin help                        Show this help

Example:
	docker exec warp-share warp-admin reset-password admin
`

func main() {
	if len(os.Args) < 2 {
		fmt.Print(usage)
		os.Exit(1)
	}

	dataDir := os.Getenv("DATA_DIR")
	if dataDir == "" {
		dataDir = "/data"
	}
	dbPath := filepath.Join(dataDir, "warp-share.sqlite")

	switch os.Args[1] {
	case "reset-password":
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "Error: Username required")
			fmt.Fprintln(os.Stderr, "Usage: warp-admin reset-password <username>")
			os.Exit(1)
		}
		username := os.Args[2]
		if err := resetPassword(dbPath, dataDir, username); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

	case "list-users":
		if err := listUsers(dbPath); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

	case "help", "-h", "--help":
		fmt.Print(usage)

	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", os.Args[1])
		fmt.Print(usage)
		os.Exit(1)
	}
}

func randomPassword() string {
	b := make([]byte, 18) // 18 bytes = 24 chars base64
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func resetPassword(dbPath, dataDir, username string) error {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer func() { _ = db.Close() }()

	// Check if user exists
	var userID int64
	err = db.QueryRow("SELECT id FROM users WHERE username = ?", username).Scan(&userID)
	if err == sql.ErrNoRows {
		return fmt.Errorf("user '%s' not found", username)
	}
	if err != nil {
		return fmt.Errorf("database error: %w", err)
	}

	// Generate random password
	password := randomPassword()

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("generate hash: %w", err)
	}

	// Update password without forcing password change
	_, err = db.Exec("UPDATE users SET password_hash = ?, must_change_password = 0 WHERE id = ?", string(hash), userID)
	if err != nil {
		return fmt.Errorf("save password: %w", err)
	}

	// Invalidate all user sessions
	res, err := db.Exec("DELETE FROM sessions WHERE user_id = ?", userID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Could not delete sessions: %v\n", err)
	} else if n, _ := res.RowsAffected(); n > 0 {
		fmt.Printf("%d active session(s) terminated\n", n)
	}


	passPath := filepath.Join(dataDir, "bootstrap_admin_password")
	if err := os.WriteFile(passPath, []byte(password+"\n"), 0600); err != nil {
		return fmt.Errorf("write password file: %w", err)
	}
	content, err := os.ReadFile(passPath)
	if err != nil {
		return fmt.Errorf("read password file: %w", err)
	}

	fmt.Printf("✓ Password for '%s' has been reset\n", username)
	fmt.Printf("  New password (from %s): %s\n", passPath, strings.TrimSpace(string(content)))
	return nil
}

func listUsers(dbPath string) error {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer func() { _ = db.Close() }()

	rows, err := db.Query("SELECT id, username, created_at FROM users ORDER BY id")
	if err != nil {
		return fmt.Errorf("query failed: %w", err)
	}
	defer func() { _ = rows.Close() }()

	fmt.Printf("%-4s %-20s %s\n", "ID", "Username", "Created")
	fmt.Println(strings.Repeat("-", 50))

	count := 0
	for rows.Next() {
		var id int64
		var username, createdAt string
		if err := rows.Scan(&id, &username, &createdAt); err != nil {
			return err
		}
		fmt.Printf("%-4d %-20s %s\n", id, username, createdAt)
		count++
	}
	if err := rows.Err(); err != nil {
		return err
	}

	if count == 0 {
		fmt.Println("(no users)")
	}
	return nil
}
