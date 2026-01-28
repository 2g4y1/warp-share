package main

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

var (
	errChallengeNotFound = errors.New("challenge not found")
	errChallengeExpired  = errors.New("challenge expired")
	errChallengeUsed     = errors.New("challenge already used")
)

type WebAuthnCredential struct {
	ID         int64
	UserID     int64
	Name       string
	CreatedAt  string
	LastUsedAt string
	Credential webauthn.Credential
}

type WebAuthnChallenge struct {
	ID          string
	UserID      sql.NullInt64
	SessionHash sql.NullString
	Type        string
	SessionJSON string
	Label       sql.NullString
	ClientIP    sql.NullString
	CreatedAt   string
	ExpiresAt   string
	Used        int64
}

func base64URL(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func base64URLDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

func (r *Repository) GetOrCreateWebAuthnHandle(ctx context.Context, userID int64) ([]byte, error) {
	var handle sql.NullString
	if err := r.db.QueryRowContext(ctx, "SELECT webauthn_handle FROM users WHERE id = ?", userID).Scan(&handle); err != nil {
		return nil, err
	}
	if handle.Valid && handle.String != "" {
		return base64URLDecode(handle.String)
	}

	raw := make([]byte, 32)
	if _, err := randRead(raw); err != nil {
		return nil, err
	}
	encoded := base64URL(raw)
	if _, err := r.db.ExecContext(ctx, "UPDATE users SET webauthn_handle = ? WHERE id = ?", encoded, userID); err != nil {
		return nil, err
	}
	return raw, nil
}

func (r *Repository) GetUserByUsername(ctx context.Context, username string) (int64, string, error) {
	var uid int64
	var uname string
	if err := r.db.QueryRowContext(ctx, "SELECT id, username FROM users WHERE username = ?", username).Scan(&uid, &uname); err != nil {
		return 0, "", err
	}
	return uid, uname, nil
}

func (r *Repository) GetUserByWebAuthnHandle(ctx context.Context, handle []byte) (int64, string, error) {
	encoded := base64URL(handle)
	var uid int64
	var username string
	if err := r.db.QueryRowContext(ctx, "SELECT id, username FROM users WHERE webauthn_handle = ?", encoded).Scan(&uid, &username); err != nil {
		return 0, "", err
	}
	return uid, username, nil
}

func (r *Repository) GetUserByCredentialID(ctx context.Context, credentialID string) (int64, string, error) {
	var uid int64
	if err := r.db.QueryRowContext(ctx, "SELECT user_id FROM webauthn_credentials WHERE credential_id = ?", credentialID).Scan(&uid); err != nil {
		return 0, "", err
	}
	var username string
	if err := r.db.QueryRowContext(ctx, "SELECT username FROM users WHERE id = ?", uid).Scan(&username); err != nil {
		return 0, "", err
	}
	return uid, username, nil
}

func (r *Repository) ListWebAuthnCredentials(ctx context.Context, userID int64) ([]WebAuthnCredential, error) {
	rows, err := r.db.QueryContext(ctx, `
SELECT id, credential_json, name, created_at, COALESCE(last_used_at, '')
FROM webauthn_credentials
WHERE user_id = ?
ORDER BY created_at DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var out []WebAuthnCredential
	for rows.Next() {
		var id int64
		var credJSON string
		var name sql.NullString
		var createdAt string
		var lastUsed string
		if err := rows.Scan(&id, &credJSON, &name, &createdAt, &lastUsed); err != nil {
			return nil, err
		}
		var cred webauthn.Credential
		if err := json.Unmarshal([]byte(credJSON), &cred); err != nil {
			return nil, err
		}
		item := WebAuthnCredential{
			ID:         id,
			UserID:     userID,
			Name:       name.String,
			CreatedAt:  createdAt,
			LastUsedAt: lastUsed,
			Credential: cred,
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (r *Repository) SaveWebAuthnCredential(ctx context.Context, userID int64, name string, cred *webauthn.Credential) error {
	if cred == nil {
		return fmt.Errorf("credential is nil")
	}
	clean := *cred
	clean.Attestation = webauthn.CredentialAttestation{}
	jsonBytes, err := json.Marshal(clean)
	if err != nil {
		return err
	}
	credID := base64URL(clean.ID)
	_, err = r.db.ExecContext(ctx, `
INSERT INTO webauthn_credentials(user_id, credential_id, credential_json, name, created_at)
VALUES(?, ?, ?, ?, ?)`,
		userID, credID, string(jsonBytes), stringsTrim(name), nowRFC3339())
	return err
}

func (r *Repository) UpdateWebAuthnCredential(ctx context.Context, userID int64, cred *webauthn.Credential) error {
	if cred == nil {
		return fmt.Errorf("credential is nil")
	}
	clean := *cred
	clean.Attestation = webauthn.CredentialAttestation{}
	jsonBytes, err := json.Marshal(clean)
	if err != nil {
		return err
	}
	credID := base64URL(clean.ID)
	_, err = r.db.ExecContext(ctx, `
UPDATE webauthn_credentials
SET credential_json = ?, last_used_at = ?
WHERE user_id = ? AND credential_id = ?`,
		string(jsonBytes), nowRFC3339(), userID, credID)
	return err
}

func (r *Repository) DeleteWebAuthnCredential(ctx context.Context, userID, id int64) error {
	_, err := r.db.ExecContext(ctx, "DELETE FROM webauthn_credentials WHERE id = ? AND user_id = ?", id, userID)
	return err
}

func (r *Repository) CreateWebAuthnChallenge(ctx context.Context, challenge WebAuthnChallenge) error {
	_, err := r.db.ExecContext(ctx, `
INSERT INTO webauthn_challenges(id, user_id, session_hash, type, session_json, label, client_ip, created_at, expires_at, used)
VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, 0)`,
		challenge.ID,
		nullableInt(challenge.UserID),
		nullableString(challenge.SessionHash),
		challenge.Type,
		challenge.SessionJSON,
		nullableString(challenge.Label),
		nullableString(challenge.ClientIP),
		challenge.CreatedAt,
		challenge.ExpiresAt,
	)
	return err
}

func (r *Repository) ConsumeWebAuthnChallenge(ctx context.Context, id, typ string) (WebAuthnChallenge, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return WebAuthnChallenge{}, err
	}
	defer func() { _ = tx.Rollback() }()

	var ch WebAuthnChallenge
	row := tx.QueryRowContext(ctx, `
SELECT id, user_id, session_hash, type, session_json, label, client_ip, created_at, expires_at, used
FROM webauthn_challenges
WHERE id = ? AND type = ?`, id, typ)
	if err := row.Scan(&ch.ID, &ch.UserID, &ch.SessionHash, &ch.Type, &ch.SessionJSON, &ch.Label, &ch.ClientIP, &ch.CreatedAt, &ch.ExpiresAt, &ch.Used); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return WebAuthnChallenge{}, errChallengeNotFound
		}
		return WebAuthnChallenge{}, err
	}
	if ch.Used != 0 {
		return WebAuthnChallenge{}, errChallengeUsed
	}
	if t, err := time.Parse(time.RFC3339, ch.ExpiresAt); err != nil || time.Now().UTC().After(t) {
		return WebAuthnChallenge{}, errChallengeExpired
	}

	res, err := tx.ExecContext(ctx, "UPDATE webauthn_challenges SET used = 1 WHERE id = ? AND used = 0", id)
	if err != nil {
		return WebAuthnChallenge{}, err
	}
	if rows, _ := res.RowsAffected(); rows == 0 {
		return WebAuthnChallenge{}, errChallengeUsed
	}

	if err := tx.Commit(); err != nil {
		return WebAuthnChallenge{}, err
	}
	return ch, nil
}

func (r *Repository) CleanupExpiredWebAuthnChallenges(ctx context.Context) (int64, error) {
	res, err := r.db.ExecContext(ctx, "DELETE FROM webauthn_challenges WHERE expires_at <= ? OR used = 1", nowRFC3339())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func nullableString(v sql.NullString) any {
	if v.Valid {
		return v.String
	}
	return nil
}

func nullableInt(v sql.NullInt64) any {
	if v.Valid {
		return v.Int64
	}
	return nil
}

func stringsTrim(s string) string {
	return strings.TrimSpace(s)
}