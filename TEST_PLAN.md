# Test Plan

## Unit Tests
- Repository: WebAuthn handle lifecycle
- Repository: credential store/list/update/delete
- Repository: challenge consume/replay
- Handler: passkey login start returns 404 when disabled

## How to Run
From /opt/warp-share/sharesvc:
- go test ./...

## Manual Verification
1. Set PASSKEYS_ENABLED=true and configure PASSKEYS_RP_ID/PASSKEYS_RP_ORIGINS.
2. Login with password and register a passkey in Settings.
3. Logout and use “Login with Passkey”.
4. Remove passkey and verify login is no longer available.
