package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// Repository encapsulates all database access
type Repository struct {
	db *sql.DB
}

func NewRepository(db *sql.DB) *Repository {
	return &Repository{db: db}
}

func (r *Repository) InitDB() error {
	schema := `
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA cache_size = -64000;
PRAGMA temp_store = MEMORY;
PRAGMA busy_timeout = 5000;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  created_at TEXT NOT NULL,
  must_change_password INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS sessions (
  id INTEGER PRIMARY KEY,
  token_hash TEXT NOT NULL UNIQUE,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS shares (
  id INTEGER PRIMARY KEY,
  slug TEXT NOT NULL UNIQUE,
  file_relpath TEXT NOT NULL,
  created_at TEXT NOT NULL,
	created_by INTEGER REFERENCES users(id),
	is_upload INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS links (
  id INTEGER PRIMARY KEY,
  share_id INTEGER NOT NULL REFERENCES shares(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL,
  expires_at TEXT,
  max_downloads INTEGER NOT NULL DEFAULT 1,
  max_downloads_per_ip INTEGER,
  used_downloads INTEGER NOT NULL DEFAULT 0,
  disabled INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS link_ip_usage (
  link_id INTEGER NOT NULL REFERENCES links(id) ON DELETE CASCADE,
  ip TEXT NOT NULL,
  downloads INTEGER NOT NULL DEFAULT 0,
  last_at TEXT NOT NULL,
  PRIMARY KEY (link_id, ip)
);

CREATE TABLE IF NOT EXISTS webauthn_credentials (
	id INTEGER PRIMARY KEY,
	user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	credential_id TEXT NOT NULL UNIQUE,
	credential_json TEXT NOT NULL,
	name TEXT,
	created_at TEXT NOT NULL,
	last_used_at TEXT
);

CREATE TABLE IF NOT EXISTS webauthn_challenges (
	id TEXT PRIMARY KEY,
	user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
	session_hash TEXT,
	type TEXT NOT NULL,
	session_json TEXT NOT NULL,
	label TEXT,
	client_ip TEXT,
	created_at TEXT NOT NULL,
	expires_at TEXT NOT NULL,
	used INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_links_share ON links(share_id);
CREATE INDEX IF NOT EXISTS idx_links_token ON links(token_hash);
CREATE INDEX IF NOT EXISTS idx_shares_relpath ON shares(file_relpath);
CREATE INDEX IF NOT EXISTS idx_shares_slug ON shares(slug);
CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token_hash);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_link_ip_usage_last ON link_ip_usage(last_at);
CREATE INDEX IF NOT EXISTS idx_webauthn_credentials_user ON webauthn_credentials(user_id);
CREATE INDEX IF NOT EXISTS idx_webauthn_challenges_expires ON webauthn_challenges(expires_at);
`
	if _, err := r.db.Exec(schema); err != nil {
		return err
	}

	if err := r.ensureUploadColumn(); err != nil {
		return err
	}

	if err := r.ensureMustChangePasswordColumn(); err != nil {
		return err
	}

	if err := r.ensureWebAuthnHandleColumn(); err != nil {
		return err
	}

	return nil
}

func (r *Repository) ensureUploadColumn() error {
	rows, err := r.db.Query("PRAGMA table_info(shares)")
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull int
		var dflt sql.NullString
		var pk int
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return err
		}
		if name == "is_upload" {
			return nil
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}

	_, err = r.db.Exec("ALTER TABLE shares ADD COLUMN is_upload INTEGER NOT NULL DEFAULT 0")
	return err
}

func (r *Repository) ensureMustChangePasswordColumn() error {
	rows, err := r.db.Query("PRAGMA table_info(users)")
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull int
		var dflt sql.NullString
		var pk int
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return err
		}
		if name == "must_change_password" {
			return nil
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}

	_, err = r.db.Exec("ALTER TABLE users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0")
	return err
}

func (r *Repository) ensureWebAuthnHandleColumn() error {
	rows, err := r.db.Query("PRAGMA table_info(users)")
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull int
		var dflt sql.NullString
		var pk int
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return err
		}
		if name == "webauthn_handle" {
			_, _ = r.db.Exec("CREATE INDEX IF NOT EXISTS idx_users_webauthn_handle ON users(webauthn_handle)")
			return nil
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}

	if _, err := r.db.Exec("ALTER TABLE users ADD COLUMN webauthn_handle TEXT"); err != nil {
		return err
	}
	_, err = r.db.Exec("CREATE INDEX IF NOT EXISTS idx_users_webauthn_handle ON users(webauthn_handle)")
	return err
}

func (r *Repository) BootstrapAdmin(username, password string) (generatedPassword string, err error) {
	var existing int
	err = r.db.QueryRow("SELECT COUNT(1) FROM users WHERE username = ?", username).Scan(&existing)
	if err != nil {
		return "", err
	}
	if existing > 0 {
		return "", nil
	}

	// Auto-generate password if not provided
	if strings.TrimSpace(password) == "" {
		password, err = generateSecurePassword()
		if err != nil {
			return "", fmt.Errorf("failed to generate admin password: %w", err)
		}
		generatedPassword = password
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	_, err = r.db.Exec(
		"INSERT INTO users(username, password_hash, created_at) VALUES(?, ?, ?)",
		username,
		string(hash),
		nowRFC3339(),
	)
	if err != nil {
		return "", err
	}
	return generatedPassword, nil
}

// generateSecurePassword creates a cryptographically secure password
func generateSecurePassword() (string, error) {
	const charset = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	// 24 chars from a ~56-char alphabet ≈ 139 bits of entropy.
	b := make([]byte, 24)
	if _, err := randRead(b); err != nil {
		return "", err
	}
	for i := range b {
		b[i] = charset[int(b[i])%len(charset)]
	}
	return string(b), nil
}

// --- Session & User Methods ---

func (r *Repository) GetSessionUser(ctx context.Context, tokenHash string) (int64, error) {
	var uid int64
	var expStr string
	if err := r.db.QueryRowContext(ctx, "SELECT user_id, expires_at FROM sessions WHERE token_hash = ?", tokenHash).Scan(&uid, &expStr); err != nil {
		return 0, err
	}
	exp, err := time.Parse(time.RFC3339, expStr)
	if err != nil {
		return 0, err
	}
	if !time.Now().UTC().Before(exp) {
		return 0, sql.ErrNoRows // Treat expired as not found
	}
	return uid, nil
}

func (r *Repository) AuthenticateUser(ctx context.Context, username, password string) (int64, error) {
	var uid int64
	var ph string
	var mustChange int64
	err := r.db.QueryRowContext(ctx, "SELECT id, password_hash, must_change_password FROM users WHERE username = ?", username).Scan(&uid, &ph, &mustChange)
	if err != nil {
		return 0, err
	}
	if err := bcrypt.CompareHashAndPassword([]byte(ph), []byte(password)); err != nil {
		return 0, err
	}
	// Return negative user ID if password change is required
	// This allows the caller to detect the condition without changing the error return
	if mustChange != 0 {
		return -uid, nil
	}
	return uid, nil
}

func (r *Repository) CreateSession(ctx context.Context, userID int64, tokenHash string, ttl time.Duration) error {
	now := time.Now().UTC()
	exp := now.Add(ttl)
	_, err := r.db.ExecContext(ctx,
		"INSERT INTO sessions(token_hash, user_id, created_at, expires_at) VALUES(?, ?, ?, ?)",
		tokenHash, userID, now.Format(time.RFC3339), exp.Format(time.RFC3339),
	)
	return err
}

func (r *Repository) CleanupExpiredSessions(ctx context.Context) (int64, error) {
	res, err := r.db.ExecContext(ctx, "DELETE FROM sessions WHERE expires_at <= ? LIMIT 1000", nowRFC3339())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// CleanupExpiredLinks removes expired and exhausted links from the database.
// Links are deleted when:
// - expired (expires_at <= now) AND at least 1 day old
// - or fully exhausted (used_downloads >= max_downloads > 0) AND at least 1 day old
func (r *Repository) CleanupExpiredLinks(ctx context.Context) (int64, error) {
	now := time.Now().UTC()
	nowStr := now.Format(time.RFC3339)
	oneDayAgo := now.Add(-24 * time.Hour).Format(time.RFC3339)

	// Delete in batches using LIMIT to avoid blocking
	_, _ = r.db.ExecContext(ctx, `
DELETE FROM link_ip_usage WHERE link_id IN (
  SELECT id FROM links
  WHERE created_at <= ?
    AND (
      (expires_at IS NOT NULL AND expires_at <= ?)
      OR (max_downloads > 0 AND used_downloads >= max_downloads)
    )
  LIMIT 1000
)`, oneDayAgo, nowStr)

	res, err := r.db.ExecContext(ctx, `
DELETE FROM links
WHERE created_at <= ?
  AND (
    (expires_at IS NOT NULL AND expires_at <= ?)
    OR (max_downloads > 0 AND used_downloads >= max_downloads)
  )
LIMIT 1000
`, oneDayAgo, nowStr)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// CleanupOrphanedShares removes shares without active links older than 30 days
func (r *Repository) CleanupOrphanedShares(ctx context.Context) (int64, error) {
	thirtyDaysAgo := time.Now().UTC().Add(-30 * 24 * time.Hour).Format(time.RFC3339)

	res, err := r.db.ExecContext(ctx, `
DELETE FROM shares
WHERE created_at <= ?
  AND id NOT IN (SELECT DISTINCT share_id FROM links)
LIMIT 500
`, thirtyDaysAgo)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// CleanupOrphanedSharesImmediate removes all shares without links (no age limit)
// Used for manual cleanup via admin UI
func (r *Repository) CleanupOrphanedSharesImmediate(ctx context.Context) (int64, error) {
	res, err := r.db.ExecContext(ctx, `
DELETE FROM shares
WHERE is_upload = 0
  AND id NOT IN (SELECT DISTINCT share_id FROM links)
`)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (r *Repository) RevokeSession(ctx context.Context, tokenHash string) error {
	_, err := r.db.ExecContext(ctx, "DELETE FROM sessions WHERE token_hash = ?", tokenHash)
	return err
}

func (r *Repository) UpdatePassword(userID int64, newHash string) error {
	// Clear must_change_password flag when password is changed
	_, err := r.db.Exec("UPDATE users SET password_hash = ?, must_change_password = 0 WHERE id = ?", newHash, userID)
	return err
}

func (r *Repository) GetUsernameByID(ctx context.Context, userID int64) (string, error) {
	var username string
	if err := r.db.QueryRowContext(ctx, "SELECT username FROM users WHERE id = ?", userID).Scan(&username); err != nil {
		return "", err
	}
	return username, nil
}

func (r *Repository) MustChangePassword(ctx context.Context, userID int64) (bool, error) {
	var mustChange int64
	if err := r.db.QueryRowContext(ctx, "SELECT must_change_password FROM users WHERE id = ?", userID).Scan(&mustChange); err != nil {
		return false, err
	}
	return mustChange != 0, nil
}

func (r *Repository) UpdateUsername(userID int64, newUsername string) error {
	_, err := r.db.Exec("UPDATE users SET username = ? WHERE id = ?", newUsername, userID)
	return err
}

// --- Share & Link Methods ---

func (r *Repository) GetGlobalStats(ctx context.Context) (int64, int64, error) {
	var totalDownloads int64
	var totalShares int64

	if err := r.db.QueryRowContext(ctx, "SELECT COALESCE(SUM(used_downloads),0) FROM links").Scan(&totalDownloads); err != nil {
		return 0, 0, err
	}
	if err := r.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM shares").Scan(&totalShares); err != nil {
		return 0, 0, err
	}
	return totalDownloads, totalShares, nil
}

type StatsTopFile struct {
	RelPath   string
	Downloads int64
}

func (r *Repository) GetTopFiles(ctx context.Context) ([]StatsTopFile, error) {
	rows, err := r.db.QueryContext(ctx, `
SELECT s.file_relpath, SUM(l.used_downloads) as total
FROM shares s
JOIN links l ON l.share_id = s.id
GROUP BY s.id
ORDER BY total DESC
LIMIT 10
`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var result []StatsTopFile
	for rows.Next() {
		var tf StatsTopFile
		if err := rows.Scan(&tf.RelPath, &tf.Downloads); err != nil {
			return nil, err
		}
		result = append(result, tf)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

type StatsRecentActivity struct {
	RelPath       string
	IP            string
	LastAt        string
	Downloads     int64
	MaxDownloads  int64
	UsedDownloads int64
}

func (r *Repository) GetRecentActivity(ctx context.Context) ([]StatsRecentActivity, error) {
	rows, err := r.db.QueryContext(ctx, `
SELECT s.file_relpath, lip.ip, lip.last_at, lip.downloads, l.max_downloads, l.used_downloads
FROM link_ip_usage lip
JOIN links l ON l.id = lip.link_id
JOIN shares s ON s.id = l.share_id
ORDER BY lip.last_at DESC
LIMIT 25
`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var result []StatsRecentActivity
	for rows.Next() {
		var ra StatsRecentActivity
		if err := rows.Scan(&ra.RelPath, &ra.IP, &ra.LastAt, &ra.Downloads, &ra.MaxDownloads, &ra.UsedDownloads); err != nil {
			return nil, err
		}
		result = append(result, ra)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

// LinkRow represents a single link in the history
type LinkRow struct {
	LinkID        int64
	ShareSlug     string
	FileRelPath   string
	CreatedAt     string
	ExpiresAt     sql.NullString
	MaxDownloads  int64
	UsedDownloads int64
	Disabled      int64
}

// ListLinksWithStats lists each link individually (not aggregated per share)
// Sort: active links first (by creation desc), then inactive
func (r *Repository) ListLinksWithStats(ctx context.Context) ([]LinkRow, error) {
	now := nowRFC3339()
	rows, err := r.db.QueryContext(ctx, `
SELECT l.id, s.slug, s.file_relpath, l.created_at, l.expires_at, l.max_downloads, l.used_downloads, l.disabled,
       CASE
         WHEN l.disabled = 1 THEN 1
         WHEN l.expires_at IS NOT NULL AND l.expires_at <= ? THEN 1
         WHEN l.max_downloads > 0 AND l.used_downloads >= l.max_downloads THEN 1
         ELSE 0
       END AS is_inactive
FROM links l
JOIN shares s ON s.id = l.share_id
ORDER BY is_inactive ASC, l.created_at DESC
LIMIT 200
`, now)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var result []LinkRow
	for rows.Next() {
		var l LinkRow
		var isInactive int // not used, only for Scan
		if err := rows.Scan(&l.LinkID, &l.ShareSlug, &l.FileRelPath, &l.CreatedAt, &l.ExpiresAt, &l.MaxDownloads, &l.UsedDownloads, &l.Disabled, &isInactive); err != nil {
			return nil, err
		}
		result = append(result, l)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

// DeleteLink deletes a single link and associated IP usage
func (r *Repository) DeleteLink(ctx context.Context, linkID int64) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	// Delete IP usage
	_, err = tx.ExecContext(ctx, "DELETE FROM link_ip_usage WHERE link_id = ?", linkID)
	if err != nil {
		return err
	}

	// Delete link
	_, err = tx.ExecContext(ctx, "DELETE FROM links WHERE id = ?", linkID)
	if err != nil {
		return err
	}

	return tx.Commit()
}

// DeleteAllInactiveLinks deletes all inactive links (disabled, expired, exhausted)
func (r *Repository) DeleteAllInactiveLinks(ctx context.Context) (int64, error) {
	now := nowRFC3339()

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()

	// Delete IP usage for inactive links
	_, err = tx.ExecContext(ctx, `
DELETE FROM link_ip_usage WHERE link_id IN (
  SELECT id FROM links
  WHERE disabled = 1
     OR (expires_at IS NOT NULL AND expires_at <= ?)
     OR (max_downloads > 0 AND used_downloads >= max_downloads)
)`, now)
	if err != nil {
		return 0, err
	}

	// Delete inactive links
	res, err := tx.ExecContext(ctx, `
DELETE FROM links
WHERE disabled = 1
   OR (expires_at IS NOT NULL AND expires_at <= ?)
   OR (max_downloads > 0 AND used_downloads >= max_downloads)
`, now)
	if err != nil {
		return 0, err
	}

	if err := tx.Commit(); err != nil {
		return 0, err
	}

	return res.RowsAffected()
}

func (r *Repository) CreateShare(ctx context.Context, slug, relPath string, userID int64, isUpload bool) (int64, error) {
	flag := 0
	if isUpload {
		flag = 1
	}
	res, err := r.db.ExecContext(ctx,
		"INSERT INTO shares(slug, file_relpath, created_at, created_by, is_upload) VALUES(?, ?, ?, ?, ?)",
		slug, relPath, nowRFC3339(), userID, flag,
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

type uploadShare struct {
	ID      int64
	RelPath string
}

func (r *Repository) ListOrphanedUploadShares(ctx context.Context, limit int) ([]uploadShare, error) {
	rows, err := r.db.QueryContext(ctx, `
SELECT s.id, s.file_relpath
FROM shares s
WHERE s.is_upload = 1
  AND s.id NOT IN (SELECT DISTINCT share_id FROM links)
LIMIT ?
`, limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var out []uploadShare
	for rows.Next() {
		var u uploadShare
		if err := rows.Scan(&u.ID, &u.RelPath); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (r *Repository) DeleteShare(ctx context.Context, shareID int64) error {
	_, err := r.db.ExecContext(ctx, "DELETE FROM shares WHERE id = ?", shareID)
	return err
}

func (r *Repository) CreateLink(ctx context.Context, shareID int64, tokenHash string, maxDL int64, expiresAt *string, maxDLPerIP *int64) error {
	_, err := r.db.ExecContext(ctx, `
INSERT INTO links(share_id, token_hash, created_at, expires_at, max_downloads, max_downloads_per_ip)
VALUES(?, ?, ?, ?, ?, ?)
`, shareID, tokenHash, nowRFC3339(), expiresAt, maxDL, maxDLPerIP)
	return err
}

func (r *Repository) DisableLink(ctx context.Context, linkID int64) error {
	_, err := r.db.ExecContext(ctx, "UPDATE links SET disabled = 1 WHERE id = ?", linkID)
	return err
}

func (r *Repository) GetShareIDBySlug(ctx context.Context, slug string) (int64, error) {
	var id int64
	if err := r.db.QueryRowContext(ctx, "SELECT id FROM shares WHERE slug = ?", slug).Scan(&id); err != nil {
		return 0, err
	}
	return id, nil
}

func (r *Repository) GetShareSlugByPath(ctx context.Context, relPath string) (string, error) {
	var slug string
	if err := r.db.QueryRowContext(ctx, "SELECT slug FROM shares WHERE file_relpath = ?", relPath).Scan(&slug); err != nil {
		return "", err
	}
	return slug, nil
}
func (r *Repository) GetShareRelPath(ctx context.Context, slug string) (string, error) {
	var relPath string
	if err := r.db.QueryRowContext(ctx, "SELECT file_relpath FROM shares WHERE slug = ?", slug).Scan(&relPath); err != nil {
		return "", err
	}
	return relPath, nil
}
func (r *Repository) CreateQuickLink(ctx context.Context, slug, tokenHash string, maxDownloads int64) error {
	expiresAt := time.Now().UTC().Add(7 * 24 * time.Hour).Format(time.RFC3339)
	_, err := r.db.ExecContext(ctx, `
INSERT INTO links(share_id, token_hash, created_at, expires_at, max_downloads, max_downloads_per_ip)
SELECT id, ?, ?, ?, ?, NULL FROM shares WHERE slug = ?
`, tokenHash, nowRFC3339(), expiresAt, maxDownloads, slug)
	return err
}

func (r *Repository) ConsumeLink(ctx context.Context, shareSlug, tokenHash, clientIP string, now time.Time, grantTTL time.Duration) (string, bool) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return "", false
	}
	defer func() { _ = tx.Rollback() }()

	// CRITICAL FIX for NEEDS_VERIFICATION-001: Race condition in download counting
	//
	// Acquire RESERVED lock BEFORE reading any data by performing a write operation.
	// SQLite uses "BEGIN DEFERRED" by default, which only acquires RESERVED lock
	// when the first write occurs. Multiple concurrent transactions can all read
	// used_downloads=X, then all try to increment it, leading to lost updates.
	//
	// This dummy INSERT forces SQLite to acquire RESERVED lock immediately,
	// serializing all ConsumeLink transactions. Combined with busy_timeout in the
	// connection string, this ensures proper queuing instead of SQLITE_BUSY errors.
	//
	// The INSERT will never actually insert (id=-1 violates constraints or never matches),
	// but triggers lock acquisition.
	if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO links (id) VALUES (-1)`); err != nil {
		return "", false
	}

	var (
		linkID        int64
		fileRelPath   string
		expiresAtNull sql.NullString
		maxDownloads  int64
		usedDownloads int64
		maxPerIPNull  sql.NullInt64
		disabled      int64
	)

	err = tx.QueryRowContext(ctx, `
SELECT l.id, s.file_relpath, l.expires_at, l.max_downloads, l.used_downloads, l.max_downloads_per_ip, l.disabled
FROM links l
JOIN shares s ON s.id = l.share_id
WHERE s.slug = ? AND l.token_hash = ?
LIMIT 1
`, shareSlug, tokenHash).Scan(&linkID, &fileRelPath, &expiresAtNull, &maxDownloads, &usedDownloads, &maxPerIPNull, &disabled)
	if err != nil {
		return "", false
	}

	if disabled != 0 {
		return "", false
	}

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
	} else if !errors.Is(usageErr, sql.ErrNoRows) {
		return "", false
	}

	if sessionActive {
		_, _ = tx.ExecContext(ctx, `
UPDATE link_ip_usage SET last_at = ? WHERE link_id = ? AND ip = ?
`, now.Format(time.RFC3339), linkID, clientIP)
		if err := tx.Commit(); err != nil {
			return "", false
		}
		return fileRelPath, true
	}

	if expiresAtNull.Valid {
		exp, err := time.Parse(time.RFC3339, expiresAtNull.String)
		if err != nil {
			return "", false
		}
		if !now.Before(exp) {
			return "", false
		}
	}
	if maxDownloads > 0 && usedDownloads >= maxDownloads {
		return "", false
	}
	if maxPerIPNull.Valid && maxPerIPNull.Int64 > 0 {
		if ipStarts >= maxPerIPNull.Int64 {
			return "", false
		}
	}

	res, err := tx.ExecContext(ctx, `
UPDATE links
SET used_downloads = used_downloads + 1
WHERE id = ?
  AND disabled = 0
  AND (? = 0 OR used_downloads < ?)
  AND (expires_at IS NULL OR expires_at > ?)
`, linkID, maxDownloads, maxDownloads, now.Format(time.RFC3339))
	if err != nil {
		return "", false
	}
	affected, err := res.RowsAffected()
	if err != nil || affected != 1 {
		return "", false
	}

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

func (r *Repository) PeekLink(ctx context.Context, shareSlug, tokenHash, clientIP string, now time.Time, grantTTL time.Duration) (filePath string, maxDL, usedDL int64, ok bool) {
	var (
		fileRelPath   string
		expiresAtNull sql.NullString
		maxDownloads  int64
		usedDownloads int64
		disabled      int64
		ipLastAtStr   sql.NullString
	)

	// Note: l.id is selected for the subquery but not used in Go code
	var unusedLinkID int64
	err := r.db.QueryRowContext(ctx, `
SELECT l.id, s.file_relpath, l.expires_at, l.max_downloads, l.used_downloads, l.disabled,
       (SELECT last_at FROM link_ip_usage WHERE link_id = l.id AND ip = ? LIMIT 1) AS ip_last_at
FROM links l
JOIN shares s ON s.id = l.share_id
WHERE s.slug = ? AND l.token_hash = ?
LIMIT 1
`, clientIP, shareSlug, tokenHash).Scan(&unusedLinkID, &fileRelPath, &expiresAtNull, &maxDownloads, &usedDownloads, &disabled, &ipLastAtStr)
	if err != nil {
		return "", 0, 0, false
	}
	if disabled != 0 {
		return "", 0, 0, false
	}

	sessionActive := false
	if ipLastAtStr.Valid {
		if t, err := time.Parse(time.RFC3339, ipLastAtStr.String); err == nil {
			sessionActive = now.Sub(t) < grantTTL
		}
	}

	if sessionActive {
		return fileRelPath, maxDownloads, usedDownloads, true
	}

	if expiresAtNull.Valid {
		exp, err := time.Parse(time.RFC3339, expiresAtNull.String)
		if err != nil {
			return "", 0, 0, false
		}
		if !now.Before(exp) {
			return "", 0, 0, false
		}
	}
	if maxDownloads > 0 && usedDownloads >= maxDownloads {
		return "", 0, 0, false
	}
	return fileRelPath, maxDownloads, usedDownloads, true
}
