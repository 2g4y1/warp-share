#!/bin/bash
# WARP SHARE - Deployment Script with SRI (Subresource Integrity)
# This script generates SRI hashes for static assets to prevent integrity mismatches

set -e

# ── Colors ───────────────────────────────────────────────────────────────────
CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
DIM='\033[2m'
NC='\033[0m'

# ── Helper Functions ─────────────────────────────────────────────────────────
info()    { echo -e "${CYAN}▸${NC} $1"; }
success() { echo -e "${GREEN}✓${NC} $1"; }
warn()    { echo -e "${YELLOW}⚠${NC} $1"; }
error()   { echo -e "${RED}✗${NC} $1"; }
section() { echo -e "\n${DIM}── $1 ──${NC}"; }

# ── Check dependencies ───────────────────────────────────────────────────────
command -v openssl >/dev/null 2>&1 || { error "openssl not found"; exit 1; }

echo -e "\n${CYAN}══════════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}              WARP SHARE · Deployment with SRI${NC}"
echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"

# ── Generate SRI hashes for static assets ────────────────────────────────────
section "Generating SRI Hashes"

ASSETS_DIR="${ASSETS_DIR:-./sharesvc/cmd/sharesvc/assets}"

if [ ! -d "$ASSETS_DIR" ]; then
    error "Assets directory not found: $ASSETS_DIR"
    exit 1
fi

# Function to generate SRI hash for a file
generate_sri() {
    local file="$1"
    if [ ! -f "$file" ]; then
        warn "File not found: $file"
        return 1
    fi
    
    # Generate SHA384 hash (recommended for SRI)
    local hash=$(openssl dgst -sha384 -binary "$file" | openssl base64 -A)
    echo "sha384-${hash}"
}

# Generate SRI for CSS files
info "Generating SRI for CSS files..."

BASE_CSS_SRI=""
LANDING_CSS_SRI=""
ADMIN_CSS_SRI=""
BROWSE_CSS_SRI=""
LOGIN_CSS_SRI=""

if [ -f "$ASSETS_DIR/base.css" ]; then
    BASE_CSS_SRI=$(generate_sri "$ASSETS_DIR/base.css")
    success "base.css: $BASE_CSS_SRI"
fi

if [ -f "$ASSETS_DIR/landing.css" ]; then
    LANDING_CSS_SRI=$(generate_sri "$ASSETS_DIR/landing.css")
    success "landing.css: $LANDING_CSS_SRI"
fi

if [ -f "$ASSETS_DIR/admin.css" ]; then
    ADMIN_CSS_SRI=$(generate_sri "$ASSETS_DIR/admin.css")
    success "admin.css: $ADMIN_CSS_SRI"
fi

if [ -f "$ASSETS_DIR/browse.css" ]; then
    BROWSE_CSS_SRI=$(generate_sri "$ASSETS_DIR/browse.css")
    success "browse.css: $BROWSE_CSS_SRI"
fi

if [ -f "$ASSETS_DIR/login.css" ]; then
    LOGIN_CSS_SRI=$(generate_sri "$ASSETS_DIR/login.css")
    success "login.css: $LOGIN_CSS_SRI"
fi

# Generate SRI for JS files
info "Generating SRI for JavaScript files..."

PUBLIC_JS_SRI=""
ADMIN_JS_SRI=""
LOGIN_JS_SRI=""
SW_JS_SRI=""

if [ -f "$ASSETS_DIR/public.js" ]; then
    PUBLIC_JS_SRI=$(generate_sri "$ASSETS_DIR/public.js")
    success "public.js: $PUBLIC_JS_SRI"
fi

if [ -f "$ASSETS_DIR/admin.js" ]; then
    ADMIN_JS_SRI=$(generate_sri "$ASSETS_DIR/admin.js")
    success "admin.js: $ADMIN_JS_SRI"
fi

if [ -f "$ASSETS_DIR/login.js" ]; then
    LOGIN_JS_SRI=$(generate_sri "$ASSETS_DIR/login.js")
    success "login.js: $LOGIN_JS_SRI"
fi

if [ -f "$ASSETS_DIR/sw.js" ]; then
    SW_JS_SRI=$(generate_sri "$ASSETS_DIR/sw.js")
    success "sw.js: $SW_JS_SRI"
fi

# ── Generate SRI configuration file ──────────────────────────────────────────
section "Generating SRI Configuration"

SRI_CONFIG_FILE="${SRI_CONFIG_FILE:-./sri-hashes.env}"

cat > "$SRI_CONFIG_FILE" <<EOF
# Subresource Integrity (SRI) Hashes for WARP SHARE
# Generated on: $(date -u +"%Y-%m-%d %H:%M:%S UTC")
#
# These hashes ensure the integrity of static assets and prevent
# integrity mismatches when using preload links or external CDNs.
#
# Regenerate this file after updating any static assets:
#   ./deploy.sh

# CSS Files
BASE_CSS_SRI="${BASE_CSS_SRI}"
LANDING_CSS_SRI="${LANDING_CSS_SRI}"
ADMIN_CSS_SRI="${ADMIN_CSS_SRI}"
BROWSE_CSS_SRI="${BROWSE_CSS_SRI}"
LOGIN_CSS_SRI="${LOGIN_CSS_SRI}"

# JavaScript Files
PUBLIC_JS_SRI="${PUBLIC_JS_SRI}"
ADMIN_JS_SRI="${ADMIN_JS_SRI}"
LOGIN_JS_SRI="${LOGIN_JS_SRI}"
SW_JS_SRI="${SW_JS_SRI}"

# Combined CSS SRI (for concatenated stylesheets)
# For warp-share.css (base.css + landing.css combined)
# Note: If you concatenate files, you need to compute SRI on the combined output
WARP_SHARE_CSS_SRI=""
EOF

success "SRI configuration written to: $SRI_CONFIG_FILE"

# ── Display usage information ────────────────────────────────────────────────
section "Usage Information"

info "To use these SRI hashes in HTML preload links:"
echo -e "  ${DIM}<link rel=\"preload\" href=\"/warp-share.css\" as=\"style\" integrity=\"\${WARP_SHARE_CSS_SRI}\" crossorigin>${NC}"
echo -e "  ${DIM}<link rel=\"stylesheet\" href=\"/warp-share.css\" integrity=\"\${WARP_SHARE_CSS_SRI}\" crossorigin>${NC}"

info "To add SRI to your HTML templates, include the integrity attribute:"
echo -e "  ${DIM}<link rel=\"stylesheet\" href=\"/style.css\" integrity=\"sha384-...\" crossorigin>${NC}"

warn "Note: SRI hashes must be updated whenever asset files change"
warn "Service Worker (sw.js) should NOT have SRI as it needs to be fetched independently"

echo -e "\n${GREEN}✓${NC} Deployment SRI generation complete!"
echo -e "${DIM}For preload links, add the integrity attribute with the generated hash${NC}\n"
