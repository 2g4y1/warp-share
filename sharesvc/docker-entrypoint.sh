#!/bin/sh
set -eu

DATA_DIR="${DATA_DIR:-/data}"
APP_UID=$(id -u sharesvc)
APP_GID=$(id -g sharesvc)

mkdir -p "$DATA_DIR"
chown -R sharesvc:sharesvc "$DATA_DIR"

# Check upload directory permissions
if [ -n "${UPLOAD_TEMP_DIR:-}" ] && [ -d "$UPLOAD_TEMP_DIR" ]; then
    if ! su-exec sharesvc:sharesvc touch "$UPLOAD_TEMP_DIR/.write_test" 2>/dev/null; then
        echo "ERROR: Cannot write to UPLOAD_TEMP_DIR ($UPLOAD_TEMP_DIR)" >&2
        echo "  Fix: chown -R $APP_UID:$APP_GID <host-path>" >&2
    else
        rm -f "$UPLOAD_TEMP_DIR/.write_test"
    fi
fi

if [ -n "${UPLOAD_TARGET_DIR:-}" ] && [ -d "$UPLOAD_TARGET_DIR" ]; then
    if ! su-exec sharesvc:sharesvc touch "$UPLOAD_TARGET_DIR/.write_test" 2>/dev/null; then
        echo "ERROR: Cannot write to UPLOAD_TARGET_DIR ($UPLOAD_TARGET_DIR)" >&2
        echo "  Fix: chown -R $APP_UID:$APP_GID <host-path>" >&2
    else
        rm -f "$UPLOAD_TARGET_DIR/.write_test"
    fi
fi

exec su-exec sharesvc:sharesvc /usr/local/bin/warp-share
