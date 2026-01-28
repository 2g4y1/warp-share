# Implementation Notes

## WebAuthn Library
- Uses github.com/go-webauthn/webauthn (v0.15.0).
- Challenges stored server-side in SQLite with single-use and expiry validation.

## Session Binding
- Registration challenges are bound to the current admin session via session cookie hash.
- Login challenges are bound to client IP to reduce replay risk.

## Credential Storage
- Credentials stored as JSON (without attestation payload) plus a separate credential_id index.
- Updated on each login to refresh sign count and last_used_at.

## Security Decisions
- User verification default: preferred.
- Resident keys default: required to support discoverable login.
- Attestation default: none.
- HTTPS required by browsers for WebAuthn; relies on existing TLS termination.

## Fallback
- Password login remains available and unchanged.
- If passkeys disabled, UI controls are hidden and endpoints return not found.

## Rate Limiting
- Passkey login uses the existing IP-based rate limiting used for password login.
