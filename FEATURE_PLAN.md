# Passkeys/WebAuthn Feature Plan

## Scope
Add optional Passkey (WebAuthn) authentication for the admin UI while keeping existing password login intact.

## Current Entry Points
- Admin login: /sharesvc/cmd/sharesvc/auth.go
- Admin settings: /sharesvc/cmd/sharesvc/handlers_admin.go
- Routing: /sharesvc/cmd/sharesvc/main.go
- Templates: /sharesvc/cmd/sharesvc/assets/login.html, admin.html
- Database: /sharesvc/cmd/sharesvc/db.go

## Proposed Routes
Admin (authenticated + CSRF):
- GET {ADMIN_PATH}/passkeys
- POST {ADMIN_PATH}/passkeys/register/start
- POST {ADMIN_PATH}/passkeys/register/finish
- POST {ADMIN_PATH}/passkeys/delete

Unauthenticated (login):
- POST {ADMIN_PATH}/passkeys/login/start
- POST {ADMIN_PATH}/passkeys/login/finish

Static asset:
- GET {ADMIN_PATH}/static/login.js

## Data Model Changes
SQLite tables:
- webauthn_credentials: store WebAuthn credential JSON, user_id, label, timestamps
- webauthn_challenges: store session data for registration/login with expiry and single-use

Users table:
- add webauthn_handle column for stable WebAuthn user handle

## Feature Flags / Config
- PASSKEYS_ENABLED (default false)
- PASSKEYS_RP_ID / PASSKEYS_RP_ORIGINS / PASSKEYS_RP_DISPLAY_NAME
- PASSKEYS_TIMEOUT, PASSKEYS_USER_VERIFICATION, PASSKEYS_RESIDENT_KEY
- PASSKEYS_AUTHENTICATOR_ATTACHMENT, PASSKEYS_ATTESTATION

## Test Plan (high level)
- Unit tests for handle generation, credential storage, challenge lifecycle
- Handler gating test for disabled passkeys

## Acceptance Criteria
- Passkey registration + login works end-to-end (if enabled)
- Password login remains fully functional
- DB schema migrates safely
- No secrets committed; configuration documented
- Clear rollback path
