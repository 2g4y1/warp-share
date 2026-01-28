package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
)

type webauthnUser struct {
	id          int64
	handle      []byte
	username    string
	credentials []webauthn.Credential
}

func (u *webauthnUser) WebAuthnID() []byte                   { return u.handle }
func (u *webauthnUser) WebAuthnName() string                 { return u.username }
func (u *webauthnUser) WebAuthnDisplayName() string          { return u.username }
func (u *webauthnUser) WebAuthnCredentials() []webauthn.Credential { return u.credentials }

func initWebAuthn(cfg config) (*webauthn.WebAuthn, error) {
	if !cfg.PasskeysEnabled {
		return nil, nil
	}
	uv, err := parseUserVerification(cfg.PasskeysUserVerification)
	if err != nil {
		return nil, err
	}
	rk, err := parseResidentKey(cfg.PasskeysResidentKey)
	if err != nil {
		return nil, err
	}
	att, err := parseAttestation(cfg.PasskeysAttestation)
	if err != nil {
		return nil, err
	}
	attach, err := parseAuthenticatorAttachment(cfg.PasskeysAuthenticatorAttach)
	if err != nil {
		return nil, err
	}

	selection := protocol.AuthenticatorSelection{UserVerification: uv}
	if rk != "" {
		selection.ResidentKey = rk
		if rk == protocol.ResidentKeyRequirementRequired {
			b := true
			selection.RequireResidentKey = &b
		}
	}
	if attach != "" {
		selection.AuthenticatorAttachment = attach
	}

	wa, err := webauthn.New(&webauthn.Config{
		RPID:                   cfg.PasskeysRPID,
		RPDisplayName:          cfg.PasskeysRPDisplayName,
		RPOrigins:              cfg.PasskeysRPOrigins,
		AttestationPreference:  att,
		AuthenticatorSelection: selection,
		Timeouts: webauthn.TimeoutsConfig{
			Login:        webauthn.TimeoutConfig{Enforce: true, Timeout: cfg.PasskeysTimeout, TimeoutUVD: cfg.PasskeysTimeout},
			Registration: webauthn.TimeoutConfig{Enforce: true, Timeout: cfg.PasskeysTimeout, TimeoutUVD: cfg.PasskeysTimeout},
		},
	})
	if err != nil {
		return nil, err
	}
	return wa, nil
}

func (a *app) passkeysEnabled() bool {
	return a != nil && a.cfg.PasskeysEnabled && a.webauthn != nil
}

func (a *app) loadWebAuthnUser(ctx context.Context, userID int64) (*webauthnUser, error) {
	username, err := a.repo.GetUsernameByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	handle, err := a.repo.GetOrCreateWebAuthnHandle(ctx, userID)
	if err != nil {
		return nil, err
	}
	creds, err := a.repo.ListWebAuthnCredentials(ctx, userID)
	if err != nil {
		return nil, err
	}
	var list []webauthn.Credential
	for _, c := range creds {
		list = append(list, c.Credential)
	}
	return &webauthnUser{userID, handle, username, list}, nil
}

func (a *app) handlePasskeyList(w http.ResponseWriter, r *http.Request) {
	if !a.passkeysEnabled() {
		jsonError(w, http.StatusNotFound, "disabled", "Passkeys disabled")
		return
	}
	uidAny := r.Context().Value(ctxKeyUserID{})
	uid, _ := uidAny.(int64)
	if uid == 0 {
		http.NotFound(w, r)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), a.cfg.DBTimeout)
	defer cancel()
	creds, err := a.repo.ListWebAuthnCredentials(ctx, uid)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "db", "Database error")
		return
	}

	type item struct {
		ID         int64  `json:"id"`
		Name       string `json:"name"`
		CreatedAt  string `json:"created_at"`
		LastUsedAt string `json:"last_used_at"`
	}
	var out []item
	for _, c := range creds {
		out = append(out, item{ID: c.ID, Name: c.Name, CreatedAt: c.CreatedAt, LastUsedAt: c.LastUsedAt})
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"enabled": true,
		"items":   out,
	})
}

func (a *app) handlePasskeyRegisterStart(w http.ResponseWriter, r *http.Request) {
	if !a.passkeysEnabled() {
		jsonError(w, http.StatusNotFound, "disabled", "Passkeys disabled")
		return
	}
	uidAny := r.Context().Value(ctxKeyUserID{})
	uid, _ := uidAny.(int64)
	if uid == 0 {
		http.NotFound(w, r)
		return
	}

	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		jsonError(w, http.StatusBadRequest, "parse_error", "Invalid request")
		return
	}
	label := strings.TrimSpace(req.Name)
	if len(label) > 64 {
		label = label[:64]
	}

	ctx, cancel := context.WithTimeout(r.Context(), a.cfg.DBTimeout)
	defer cancel()
	user, err := a.loadWebAuthnUser(ctx, uid)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "db", "Database error")
		return
	}

	var opts []webauthn.RegistrationOption
	if len(user.credentials) > 0 {
		excludes := webauthn.Credentials(user.credentials).CredentialDescriptors()
		opts = append(opts, webauthn.WithExclusions(excludes))
	}

	creation, session, err := a.webauthn.BeginRegistration(user, opts...)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "webauthn", "Unable to start registration")
		return
	}

	sessJSON, err := json.Marshal(session)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "webauthn", "Unable to create session")
		return
	}

	sessCookie, err := r.Cookie("warp_admin")
	if err != nil || strings.TrimSpace(sessCookie.Value) == "" {
		jsonError(w, http.StatusForbidden, "auth", "Session missing")
		return
	}

	challenge := WebAuthnChallenge{
		ID:          uuid.NewString(),
		UserID:      sql.NullInt64{Int64: uid, Valid: true},
		SessionHash: sql.NullString{String: sha256Hex(sessCookie.Value), Valid: true},
		Type:        "registration",
		SessionJSON: string(sessJSON),
		Label:       sql.NullString{String: label, Valid: label != ""},
		ClientIP:    sql.NullString{String: getClientIP(r), Valid: true},
		CreatedAt:   nowRFC3339(),
		ExpiresAt:   session.Expires.UTC().Format(time.RFC3339),
	}
	if err := a.repo.CreateWebAuthnChallenge(ctx, challenge); err != nil {
		jsonError(w, http.StatusInternalServerError, "db", "Database error")
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"options":    creation,
		"session_id": challenge.ID,
	})
}

func (a *app) handlePasskeyRegisterFinish(w http.ResponseWriter, r *http.Request) {
	if !a.passkeysEnabled() {
		jsonError(w, http.StatusNotFound, "disabled", "Passkeys disabled")
		return
	}
	uidAny := r.Context().Value(ctxKeyUserID{})
	uid, _ := uidAny.(int64)
	if uid == 0 {
		http.NotFound(w, r)
		return
	}
	challengeID := strings.TrimSpace(r.Header.Get("X-WA-Session"))
	if challengeID == "" {
		jsonError(w, http.StatusBadRequest, "invalid", "Missing session")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), a.cfg.DBTimeout)
	defer cancel()
	ch, err := a.repo.ConsumeWebAuthnChallenge(ctx, challengeID, "registration")
	if err != nil {
		jsonError(w, http.StatusBadRequest, "invalid", "Challenge invalid or expired")
		return
	}
	if !ch.UserID.Valid || ch.UserID.Int64 != uid {
		jsonError(w, http.StatusForbidden, "auth", "Challenge mismatch")
		return
	}
	if ch.SessionHash.Valid {
		c, err := r.Cookie("warp_admin")
		if err != nil || strings.TrimSpace(c.Value) == "" || sha256Hex(c.Value) != ch.SessionHash.String {
			jsonError(w, http.StatusForbidden, "auth", "Session mismatch")
			return
		}
	}
	if ch.ClientIP.Valid && ch.ClientIP.String != "" {
		if ip := getClientIP(r); ip != ch.ClientIP.String {
			jsonError(w, http.StatusForbidden, "auth", "Client mismatch")
			return
		}
	}

	var session webauthn.SessionData
	if err := json.Unmarshal([]byte(ch.SessionJSON), &session); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid", "Invalid session")
		return
	}

	user, err := a.loadWebAuthnUser(ctx, uid)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "db", "Database error")
		return
	}

	cred, err := a.webauthn.FinishRegistration(user, session, r)
	if err != nil {
		jsonError(w, http.StatusBadRequest, "webauthn", "Registration failed")
		return
	}

	label := ""
	if ch.Label.Valid {
		label = ch.Label.String
	}
	if err := a.repo.SaveWebAuthnCredential(ctx, uid, label, cred); err != nil {
		jsonError(w, http.StatusInternalServerError, "db", "Could not save credential")
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]any{"success": true})
}

func (a *app) handlePasskeyDelete(w http.ResponseWriter, r *http.Request) {
	if !a.passkeysEnabled() {
		jsonError(w, http.StatusNotFound, "disabled", "Passkeys disabled")
		return
	}
	uidAny := r.Context().Value(ctxKeyUserID{})
	uid, _ := uidAny.(int64)
	if uid == 0 {
		http.NotFound(w, r)
		return
	}
	var req struct {
		ID int64 `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "parse_error", "Invalid request")
		return
	}
	if req.ID <= 0 {
		jsonError(w, http.StatusBadRequest, "invalid", "Invalid id")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), a.cfg.DBTimeout)
	defer cancel()
	if err := a.repo.DeleteWebAuthnCredential(ctx, uid, req.ID); err != nil {
		jsonError(w, http.StatusInternalServerError, "db", "Delete failed")
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]any{"success": true})
}

func (a *app) handlePasskeyLoginStart(w http.ResponseWriter, r *http.Request) {
	if !a.passkeysEnabled() {
		jsonError(w, http.StatusNotFound, "disabled", "Passkeys disabled")
		return
	}
	clientIP := getClientIP(r)
	allowed, retryAfter := checkLoginRateLimit(clientIP)
	if !allowed {
		w.Header().Set("Retry-After", strconv.Itoa(int(retryAfter.Seconds())))
		jsonError(w, http.StatusTooManyRequests, "rate_limited", "Too many attempts")
		return
	}

	var req struct {
		Username string `json:"username"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		jsonError(w, http.StatusBadRequest, "parse_error", "Invalid request")
		return
	}
	username := strings.TrimSpace(req.Username)

	ctx, cancel := context.WithTimeout(r.Context(), a.cfg.DBTimeout)
	defer cancel()

	var (
		assertion *protocol.CredentialAssertion
		session   *webauthn.SessionData
		uid       int64
	)
	if username != "" {
		var err error
		uid, _, err = a.repo.GetUserByUsername(ctx, username)
		if err != nil {
			jsonError(w, http.StatusBadRequest, "not_available", "Passkey login not available")
			return
		}
		user, err := a.loadWebAuthnUser(ctx, uid)
		if err != nil || len(user.credentials) == 0 {
			jsonError(w, http.StatusBadRequest, "not_available", "Passkey login not available")
			return
		}
		assertion, session, err = a.webauthn.BeginLogin(user)
		if err != nil {
			jsonError(w, http.StatusInternalServerError, "webauthn", "Unable to start login")
			return
		}
	} else {
		var err error
		assertion, session, err = a.webauthn.BeginDiscoverableLogin()
		if err != nil {
			jsonError(w, http.StatusInternalServerError, "webauthn", "Unable to start login")
			return
		}
	}

	sessJSON, err := json.Marshal(session)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "webauthn", "Unable to create session")
		return
	}

	challenge := WebAuthnChallenge{
		ID:          uuid.NewString(),
		UserID:      sql.NullInt64{Int64: uid, Valid: uid > 0},
		SessionHash: sql.NullString{},
		Type:        "authentication",
		SessionJSON: string(sessJSON),
		ClientIP:    sql.NullString{String: clientIP, Valid: true},
		CreatedAt:   nowRFC3339(),
		ExpiresAt:   session.Expires.UTC().Format(time.RFC3339),
	}
	if err := a.repo.CreateWebAuthnChallenge(ctx, challenge); err != nil {
		jsonError(w, http.StatusInternalServerError, "db", "Database error")
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"options":    assertion,
		"session_id": challenge.ID,
	})
}

func (a *app) handlePasskeyLoginFinish(w http.ResponseWriter, r *http.Request) {
	if !a.passkeysEnabled() {
		jsonError(w, http.StatusNotFound, "disabled", "Passkeys disabled")
		return
	}
	clientIP := getClientIP(r)
	allowed, retryAfter := checkLoginRateLimit(clientIP)
	if !allowed {
		w.Header().Set("Retry-After", strconv.Itoa(int(retryAfter.Seconds())))
		jsonError(w, http.StatusTooManyRequests, "rate_limited", "Too many attempts")
		return
	}

	challengeID := strings.TrimSpace(r.Header.Get("X-WA-Session"))
	if challengeID == "" {
		jsonError(w, http.StatusBadRequest, "invalid", "Missing session")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), a.cfg.DBTimeout)
	defer cancel()
	ch, err := a.repo.ConsumeWebAuthnChallenge(ctx, challengeID, "authentication")
	if err != nil {
		recordLoginFailure(clientIP)
		jsonError(w, http.StatusBadRequest, "invalid", "Challenge invalid or expired")
		return
	}
	if ch.ClientIP.Valid && ch.ClientIP.String != "" && ch.ClientIP.String != clientIP {
		recordLoginFailure(clientIP)
		jsonError(w, http.StatusForbidden, "auth", "Client mismatch")
		return
	}

	var session webauthn.SessionData
	if err := json.Unmarshal([]byte(ch.SessionJSON), &session); err != nil {
		recordLoginFailure(clientIP)
		jsonError(w, http.StatusBadRequest, "invalid", "Invalid session")
		return
	}

	var user *webauthnUser
	var cred *webauthn.Credential
	if ch.UserID.Valid && ch.UserID.Int64 > 0 {
		user, err = a.loadWebAuthnUser(ctx, ch.UserID.Int64)
		if err != nil || user == nil {
			recordLoginFailure(clientIP)
			jsonError(w, http.StatusBadRequest, "invalid", "Login failed")
			return
		}
		cred, err = a.webauthn.FinishLogin(user, session, r)
	} else {
		var handlerUser *webauthnUser
		cred, err = a.webauthn.FinishDiscoverableLogin(func(rawID, userHandle []byte) (webauthn.User, error) {
			if len(userHandle) > 0 {
				uid, uname, err := a.repo.GetUserByWebAuthnHandle(ctx, userHandle)
				if err != nil {
					return nil, err
				}
				creds, err := a.repo.ListWebAuthnCredentials(ctx, uid)
				if err != nil {
					return nil, err
				}
				var list []webauthn.Credential
				for _, c := range creds {
					list = append(list, c.Credential)
				}
				handlerUser = &webauthnUser{uid, userHandle, uname, list}
				return handlerUser, nil
			}
			if len(rawID) == 0 {
				return nil, errors.New("missing raw id")
			}
			uid, uname, err := a.repo.GetUserByCredentialID(ctx, base64URL(rawID))
			if err != nil {
				return nil, err
			}
			h, err := a.repo.GetOrCreateWebAuthnHandle(ctx, uid)
			if err != nil {
				return nil, err
			}
			creds, err := a.repo.ListWebAuthnCredentials(ctx, uid)
			if err != nil {
				return nil, err
			}
			var list []webauthn.Credential
			for _, c := range creds {
				list = append(list, c.Credential)
			}
			handlerUser = &webauthnUser{uid, h, uname, list}
			return handlerUser, nil
		}, session, r)
		user = handlerUser
	}
	if err != nil || user == nil || cred == nil {
		recordLoginFailure(clientIP)
		jsonError(w, http.StatusBadRequest, "invalid", "Login failed")
		return
	}

	if err := a.repo.UpdateWebAuthnCredential(ctx, user.id, cred); err != nil {
		log.Printf("PASSKEY: credential update failed: %v", err)
	}

	sessToken, err := randomToken(32)
	if err != nil {
		recordLoginFailure(clientIP)
		jsonError(w, http.StatusInternalServerError, "token", "Token generation failed")
		return
	}
	if err := a.repo.CreateSession(ctx, user.id, sha256Hex(sessToken), a.cfg.SessionTTL); err != nil {
		recordLoginFailure(clientIP)
		jsonError(w, http.StatusInternalServerError, "db", "Session create failed")
		return
	}

	exp := time.Now().Add(a.cfg.SessionTTL)
	http.SetCookie(w, &http.Cookie{
		Name:     "warp_admin",
		Value:    sessToken,
		Path:     a.cfg.AdminPath + "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Expires:  exp,
	})

	clearLoginFailures(clientIP)
	log.Printf("PASSKEY LOGIN SUCCESS: ip=%s user_id=%d", clientIP, user.id)

	mustChange, _ := a.repo.MustChangePassword(ctx, user.id)
	redirect := a.cfg.AdminPath + "/"
	if mustChange {
		redirect = a.cfg.AdminPath + "/?tab=settings&must_change=1"
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "redirect": redirect})
}

func (a *app) cleanupExpiredWebAuthnChallenges() {
	if !a.passkeysEnabled() {
		return
	}
	ticker := newTicker(30 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-shutdownChan:
			log.Println("WebAuthn challenge cleanup goroutine shutting down")
			return
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			deleted, err := a.repo.CleanupExpiredWebAuthnChallenges(ctx)
			cancel()
			if err == nil && deleted > 0 {
				log.Printf("Cleaned up %d WebAuthn challenges", deleted)
			}
		}
	}
}

func parseUserVerification(v string) (protocol.UserVerificationRequirement, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "required":
		return protocol.VerificationRequired, nil
	case "discouraged":
		return protocol.VerificationDiscouraged, nil
	case "preferred", "":
		return protocol.VerificationPreferred, nil
	default:
		return "", fmt.Errorf("invalid PASSKEYS_USER_VERIFICATION: %s", v)
	}
}

func parseResidentKey(v string) (protocol.ResidentKeyRequirement, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "required":
		return protocol.ResidentKeyRequirementRequired, nil
	case "preferred", "":
		return protocol.ResidentKeyRequirementPreferred, nil
	case "discouraged":
		return protocol.ResidentKeyRequirementDiscouraged, nil
	default:
		return "", fmt.Errorf("invalid PASSKEYS_RESIDENT_KEY: %s", v)
	}
}

func parseAuthenticatorAttachment(v string) (protocol.AuthenticatorAttachment, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "any":
		return "", nil
	case "platform":
		return protocol.Platform, nil
	case "cross-platform":
		return protocol.CrossPlatform, nil
	default:
		return "", fmt.Errorf("invalid PASSKEYS_AUTHENTICATOR_ATTACHMENT: %s", v)
	}
}

func parseAttestation(v string) (protocol.ConveyancePreference, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "none", "":
		return protocol.PreferNoAttestation, nil
	case "indirect":
		return protocol.PreferIndirectAttestation, nil
	case "direct":
		return protocol.PreferDirectAttestation, nil
	case "enterprise":
		return protocol.PreferEnterpriseAttestation, nil
	default:
		return "", fmt.Errorf("invalid PASSKEYS_ATTESTATION: %s", v)
	}
}