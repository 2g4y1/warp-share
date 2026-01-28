# Rollout Plan

## Step 1 — Deploy (passkeys disabled)
- Deploy code with PASSKEYS_ENABLED unset/false.
- Verify existing admin login and basic functionality.

## Step 2 — Configure Passkeys
- Set PASSKEYS_ENABLED=true
- Set PASSKEYS_RP_ID to your domain (no scheme/port)
- Set PASSKEYS_RP_ORIGINS to comma-separated origins (e.g., https://admin.example.com)
- Optional: PASSKEYS_USER_VERIFICATION, PASSKEYS_RESIDENT_KEY, PASSKEYS_ATTESTATION

## Step 3 — Validate
- Register a passkey via Settings.
- Login with passkey.
- Verify session cookie created and access works.

## Monitoring
- Watch logs for "PASSKEY LOGIN SUCCESS" and WebAuthn errors.
- Monitor auth failure rates.

## Rollback
- Set PASSKEYS_ENABLED=false and restart.
- Passkey endpoints/UI disappear; password login remains.
- No DB rollback required.
