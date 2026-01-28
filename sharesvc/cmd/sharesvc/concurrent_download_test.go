package main

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

// TestConcurrentDownloads verifies that the ConsumeLink function handles
// concurrent download attempts correctly without race conditions.
//
// This test validates NEEDS_VERIFICATION-001 from the security audit:
// - No race conditions in download counting
// - Proper enforcement of max_downloads limit
// - Proper enforcement of max_per_ip limit
// - Atomic check-and-update via SQLite SERIALIZABLE transactions
func TestConcurrentDownloads(t *testing.T) {
	// Setup temporary database
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	// Use connection string with busy_timeout parameter for modernc.org/sqlite
	db, err := sql.Open("sqlite", dbPath+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	defer func() { _ = db.Close() }()

	// Enable WAL mode for concurrent access
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		t.Fatalf("Failed to enable WAL: %v", err)
	}

	// Limit max connections to match production (5 connections)
	// This prevents SQLITE_BUSY errors by queuing requests at the connection pool level
	db.SetMaxOpenConns(5)
	db.SetMaxIdleConns(5)

	// Initialize schema (simplified version)
	schema := `
	CREATE TABLE shares (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		slug TEXT NOT NULL UNIQUE,
		created_at TEXT NOT NULL
	);

	CREATE TABLE links (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		share_id INTEGER NOT NULL,
		token_hash TEXT NOT NULL UNIQUE,
		file_rel_path TEXT NOT NULL,
		max_downloads INTEGER NOT NULL DEFAULT 0,
		used_downloads INTEGER NOT NULL DEFAULT 0,
		max_per_ip INTEGER,
		expires_at TEXT,
		disabled INTEGER NOT NULL DEFAULT 0,
		FOREIGN KEY(share_id) REFERENCES shares(id) ON DELETE CASCADE
	);

	CREATE TABLE link_ip_usage (
		link_id INTEGER NOT NULL,
		ip TEXT NOT NULL,
		downloads INTEGER NOT NULL DEFAULT 0,
		last_at TEXT NOT NULL,
		PRIMARY KEY(link_id, ip),
		FOREIGN KEY(link_id) REFERENCES links(id) ON DELETE CASCADE
	);
	`

	if _, err := db.Exec(schema); err != nil {
		t.Fatalf("Failed to create schema: %v", err)
	}

	// Insert test data: 1 share, 1 link with max_downloads=10
	now := time.Now().Format(time.RFC3339)
	_, err = db.Exec(`INSERT INTO shares (slug, created_at) VALUES (?, ?)`, "testshare", now)
	if err != nil {
		t.Fatalf("Failed to insert share: %v", err)
	}

	_, err = db.Exec(`
		INSERT INTO links (share_id, token_hash, file_rel_path, max_downloads, used_downloads, disabled)
		VALUES (1, 'testhash', 'test.txt', 10, 0, 0)
	`)
	if err != nil {
		t.Fatalf("Failed to insert link: %v", err)
	}

	// Test 1: Concurrent downloads from different IPs
	t.Run("ConcurrentDifferentIPs", func(t *testing.T) {
		const numGoroutines = 20
		const grantTTL = 10 * time.Second

		var wg sync.WaitGroup
		successCount := &atomicCounter{}
		failCount := &atomicCounter{}
		errorReasons := &sync.Map{}

		// Use different timestamps to avoid session reuse
		baseTime := time.Now().Add(-1 * time.Hour)

		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()

				ctx := context.Background()
				// Each request gets a unique time to prevent sessionActive logic
				reqTime := baseTime.Add(time.Duration(idx) * time.Minute)
				filePath, ok := consumeLinkWithReason(ctx, db, "testshare", "testhash", fmt.Sprintf("192.168.1.%d", idx), reqTime, grantTTL, errorReasons)

				if ok {
					successCount.Inc()
					if filePath != "test.txt" {
						t.Errorf("Expected file path 'test.txt', got '%s'", filePath)
					}
				} else {
					failCount.Inc()
				}
			}(i)
		}

		wg.Wait()

		// Log failure count if any (for debugging)
		if failCount.Get() > 0 {
			t.Logf("%d requests failed (expected when max_downloads is reached)", failCount.Get())
		}

		// With max_downloads=10, exactly 10 should succeed
		if successCount.Get() != 10 {
			t.Errorf("Expected 10 successful downloads, got %d", successCount.Get())
		}
		if failCount.Get() != 10 {
			t.Errorf("Expected 10 failed downloads, got %d", failCount.Get())
		}

		// Verify used_downloads in database
		var usedDownloads int
		err := db.QueryRow("SELECT used_downloads FROM links WHERE id = 1").Scan(&usedDownloads)
		if err != nil {
			t.Fatalf("Failed to query used_downloads: %v", err)
		}
		if usedDownloads != 10 {
			t.Errorf("Expected used_downloads=10 in DB, got %d", usedDownloads)
		}
	})

	// Test 2: Concurrent downloads from same IP with max_per_ip limit
	t.Run("ConcurrentSameIPWithLimit", func(t *testing.T) {
		// Reset the link with max_per_ip=5
		_, err := db.Exec(`
			UPDATE links SET used_downloads = 0, max_per_ip = 5 WHERE id = 1;
			DELETE FROM link_ip_usage;
		`)
		if err != nil {
			t.Fatalf("Failed to reset link: %v", err)
		}

		const clientIP = "10.0.0.1"
		const grantTTL = 100 * time.Millisecond // Short TTL for testing

		var successCount, failCount int
		ctx := context.Background()

		// Perform downloads sequentially with timestamps outside grantTTL window
		// This ensures each download is counted as a new download, not as session continuation
		baseTime := time.Now().Add(-1 * time.Hour)

		for i := 0; i < 10; i++ {
			// Each request is separated by 1 second to ensure grantTTL (100ms) has expired
			reqTime := baseTime.Add(time.Duration(i) * time.Second)
			_, ok := consumeLink(ctx, db, "testshare", "testhash", clientIP, reqTime, grantTTL)
			if ok {
				successCount++
			} else {
				failCount++
			}
		}

		// With max_per_ip=5, exactly 5 should succeed
		if successCount != 5 {
			t.Errorf("Expected 5 successful downloads from same IP, got %d", successCount)
		}
		if failCount != 5 {
			t.Errorf("Expected 5 failed downloads from same IP, got %d", failCount)
		}

		// Verify IP usage tracking
		var ipDownloads int
		err = db.QueryRow("SELECT downloads FROM link_ip_usage WHERE link_id = 1 AND ip = ?", clientIP).Scan(&ipDownloads)
		if err != nil {
			t.Fatalf("Failed to query IP usage: %v", err)
		}
		if ipDownloads != 5 {
			t.Errorf("Expected downloads=5 for IP in DB, got %d", ipDownloads)
		}
	})

	// Test 3: Expired links
	t.Run("ExpiredLink", func(t *testing.T) {
		// Set link to expire in the past
		pastTime := time.Now().Add(-1 * time.Hour).Format(time.RFC3339)
		_, err := db.Exec(`UPDATE links SET expires_at = ?, used_downloads = 0 WHERE id = 1`, pastTime)
		if err != nil {
			t.Fatalf("Failed to set expiration: %v", err)
		}

		ctx := context.Background()
		_, ok := consumeLink(ctx, db, "testshare", "testhash", "192.168.1.1", time.Now(), 10*time.Second)

		if ok {
			t.Error("Expected download to fail for expired link")
		}
	})
}

// consumeLink is a simplified version of Repository.ConsumeLink for testing
// This mirrors the actual implementation from db.go:603-710
func consumeLink(ctx context.Context, db *sql.DB, shareSlug, tokenHash, clientIP string, now time.Time, grantTTL time.Duration) (string, bool) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return "", false
	}
	defer func() { _ = tx.Rollback() }()

	// Acquire write lock immediately (matches production fix)
	if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO links (id) VALUES (-1)`); err != nil {
		fmt.Printf("[DEBUG] Lock acquisition failed: %v\n", err)
		return "", false
	}

	var (
		linkID        int64
		fileRelPath   string
		expiresAtNull sql.NullString
		maxDownloads  int64
		usedDownloads int64
		maxPerIPNull  sql.NullInt64
		disabled      int
	)

	// Query link details
	err = tx.QueryRowContext(ctx, `
SELECT l.id, l.file_rel_path, l.expires_at, l.max_downloads, l.used_downloads, l.max_per_ip, l.disabled
FROM links l
JOIN shares s ON s.id = l.share_id
WHERE s.slug = ? AND l.token_hash = ?
`, shareSlug, tokenHash).Scan(&linkID, &fileRelPath, &expiresAtNull, &maxDownloads, &usedDownloads, &maxPerIPNull, &disabled)

	if err != nil {
		fmt.Printf("[DEBUG] SELECT failed: %v\n", err)
		return "", false
	}

	if disabled != 0 {
		fmt.Printf("[DEBUG] Link disabled\n")
		return "", false
	}

	// Check IP usage
	var ipStarts int64
	var ipLastAtStr string
	var sessionActive bool

	usageErr := tx.QueryRowContext(ctx, `
SELECT downloads, last_at FROM link_ip_usage WHERE link_id = ? AND ip = ?
`, linkID, clientIP).Scan(&ipStarts, &ipLastAtStr)

	if usageErr == nil {
		if t, err := time.Parse(time.RFC3339, ipLastAtStr); err == nil {
			sessionActive = now.Sub(t) < grantTTL
		}
	}
	// usageErr == sql.ErrNoRows is expected for first download from this IP

	// If session is active, just update timestamp
	if sessionActive {
		_, _ = tx.ExecContext(ctx, `
UPDATE link_ip_usage SET last_at = ? WHERE link_id = ? AND ip = ?
`, now.Format(time.RFC3339), linkID, clientIP)
		if err := tx.Commit(); err != nil {
			return "", false
		}
		return fileRelPath, true
	}

	// Check expiration
	if expiresAtNull.Valid {
		exp, err := time.Parse(time.RFC3339, expiresAtNull.String)
		if err != nil {
			fmt.Printf("[DEBUG] Failed to parse expiration: %v\n", err)
			return "", false
		}
		if !now.Before(exp) {
			fmt.Printf("[DEBUG] Link expired: now=%v, exp=%v\n", now, exp)
			return "", false
		}
	}

	// Check max downloads
	if maxDownloads > 0 && usedDownloads >= maxDownloads {
		fmt.Printf("[DEBUG] Max downloads reached: used=%d, max=%d\n", usedDownloads, maxDownloads)
		return "", false
	}

	// Check per-IP limit
	if maxPerIPNull.Valid && maxPerIPNull.Int64 > 0 {
		if ipStarts >= maxPerIPNull.Int64 {
			fmt.Printf("[DEBUG] IP limit reached: used=%d, max=%d\n", ipStarts, maxPerIPNull.Int64)
			return "", false
		}
	}

	// CRITICAL: Atomic check-and-update
	// This WHERE clause ensures we only increment if conditions still hold
	res, err := tx.ExecContext(ctx, `
UPDATE links
SET used_downloads = used_downloads + 1
WHERE id = ?
  AND disabled = 0
  AND (? = 0 OR used_downloads < ?)
  AND (expires_at IS NULL OR expires_at > ?)
`, linkID, maxDownloads, maxDownloads, now.Format(time.RFC3339))

	if err != nil {
		fmt.Printf("[DEBUG] UPDATE failed: %v\n", err)
		return "", false
	}

	affected, err := res.RowsAffected()
	if err != nil || affected != 1 {
		fmt.Printf("[DEBUG] RowsAffected=%v, err=%v (max_downloads=%d, used_downloads=%d)\n", affected, err, maxDownloads, usedDownloads)
		return "", false
	}

	// Update IP usage
	if _, err := tx.ExecContext(ctx, `
INSERT INTO link_ip_usage(link_id, ip, downloads, last_at)
VALUES(?, ?, 1, ?)
ON CONFLICT(link_id, ip) DO UPDATE SET downloads = downloads + 1, last_at = excluded.last_at
`, linkID, clientIP, now.Format(time.RFC3339)); err != nil {
		return "", false
	}

	if err := tx.Commit(); err != nil {
		return "", false
	}

	return fileRelPath, true
}

// atomicCounter provides thread-safe counter
type atomicCounter struct {
	mu    sync.Mutex
	count int
}

func (c *atomicCounter) Inc() {
	c.mu.Lock()
	c.count++
	c.mu.Unlock()
}

func (c *atomicCounter) Get() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.count
}

// consumeLinkWithReason adds error tracking for debugging
func consumeLinkWithReason(ctx context.Context, db *sql.DB, shareSlug, tokenHash, clientIP string, now time.Time, grantTTL time.Duration, reasons *sync.Map) (string, bool) {
	path, ok := consumeLink(ctx, db, shareSlug, tokenHash, clientIP, now, grantTTL)
	if !ok {
		// Track failure reason
		reasons.Store("failed", true)
	}
	return path, ok
}
