#!/bin/bash
# WARP SHARE - Setup Script
set -e

# ── Colors ───────────────────────────────────────────────────────────────────
CYAN='\033[0;36m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; DIM='\033[2m'; NC='\033[0m'

# ── Helper Functions ─────────────────────────────────────────────────────────
info()    { echo -e "${CYAN}▸${NC} $1"; }
success() { echo -e "${GREEN}✓${NC} $1"; }
warn()    { echo -e "${YELLOW}⚠${NC} $1"; }
error()   { echo -e "${RED}✗${NC} $1"; }
section() { echo -e "\n${DIM}── $1 ──${NC}"; }

is_valid_port() {
    case "$1" in
        ''|*[!0-9]*) return 1 ;;
    esac
    [ "$1" -ge 1 ] 2>/dev/null && [ "$1" -le 65535 ] 2>/dev/null
}

is_private_ipv4() {
    case "$1" in
        10.*|127.*|192.168.*) return 0 ;;
        172.1[6-9].*|172.2[0-9].*|172.3[0-1].*) return 0 ;;
        169.254.*) return 0 ;;
        *) return 1 ;;
    esac
}

# ── Check dependencies ───────────────────────────────────────────────────────

if docker compose version >/dev/null 2>&1; then
    DOCKER_COMPOSE="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then
    DOCKER_COMPOSE="docker-compose"
else
    error "Neither 'docker compose' nor 'docker-compose' found"
    exit 1
fi

command -v docker >/dev/null 2>&1 || { error "docker not found"; exit 1; }
command -v openssl >/dev/null 2>&1 || { error "openssl not found"; exit 1; }

echo -e "\n${CYAN}══════════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}                    WARP SHARE · Setup${NC}"
echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"

# ── Installation Mode ────────────────────────────────────────────────────────

section "Installation Mode"
echo -e "  ${GREEN}1)${NC} Public  ${DIM}– Let's Encrypt SSL (requires public IP + domain)${NC}"
echo -e "  ${GREEN}2)${NC} Local   ${DIM}– Self-signed cert (LAN/localhost only)${NC}"
echo -e -n "${CYAN}▸${NC} Choose [1/2]: "
read -r MODE_CHOICE

if [[ "$MODE_CHOICE" == "2" ]]; then
    LOCAL_MODE=true
    success "Local mode"
else
    LOCAL_MODE=false
    success "Public mode"
fi

# ── Check existing .env ──────────────────────────────────────────────────────

if [ -f .env ]; then
    warn ".env exists. Overwrite? (y/N)"
    read -r response
    [[ ! "$response" =~ ^[Yy]$ ]] && echo "Cancelled." && exit 0
fi

# ── Collect Configuration ────────────────────────────────────────────────────

section "Configuration"

if [ "$LOCAL_MODE" = true ]; then
    echo -e -n "${CYAN}▸${NC} Hostname/IP ${DIM}(default: localhost)${NC}: "
    read -r DOMAIN
    [ -z "$DOMAIN" ] && DOMAIN="localhost"
    EMAIL=""
else
    echo -e -n "${CYAN}▸${NC} Domain ${DIM}(e.g., share.example.com)${NC}: "
    read -r DOMAIN
    [ -z "$DOMAIN" ] && { error "Domain required"; exit 1; }

    INCLUDE_WWW=false
    if [[ "$DOMAIN" != www.* ]]; then
        DOTS=$(printf '%s' "$DOMAIN" | awk -F'.' '{print NF-1}')
        if [ "$DOTS" = "1" ]; then
            echo -e -n "${CYAN}▸${NC} Also add www.${DOMAIN} ${DIM}(recommended for apex domains)${NC}? ${DIM}[Y/n]${NC}: "
            read -r WWW_CHOICE
            [[ -z "$WWW_CHOICE" || "$WWW_CHOICE" =~ ^[Yy]$ ]] && INCLUDE_WWW=true
        else
            echo -e -n "${CYAN}▸${NC} Also add www.${DOMAIN} ${DIM}(optional)${NC}? ${DIM}[y/N]${NC}: "
            read -r WWW_CHOICE
            [[ "$WWW_CHOICE" =~ ^[Yy]$ ]] && INCLUDE_WWW=true
        fi
    fi

    echo -e -n "${CYAN}▸${NC} Email for Let's Encrypt ${DIM}(optional)${NC}: "
    read -r EMAIL
fi

echo -e -n "${CYAN}▸${NC} MEDIA_ROOT ${DIM}(path to your files, read-only)${NC}: "
read -r MEDIA_ROOT
[ -z "$MEDIA_ROOT" ] && { error "Media path required"; exit 1; }
[ ! -d "$MEDIA_ROOT" ] && { error "$MEDIA_ROOT does not exist"; exit 1; }

echo -e -n "${CYAN}▸${NC} UPLOAD_TEMP ${DIM}(default: ./temp)${NC}: "
read -r UPLOAD_TEMP
UPLOAD_TEMP=${UPLOAD_TEMP:-./temp}

# Host ports (nginx publishes these)
DEFAULT_HTTP_PORT=80
DEFAULT_HTTPS_PORT=443

echo -e -n "${CYAN}▸${NC} HTTP port ${DIM}(host port for nginx, default: ${DEFAULT_HTTP_PORT})${NC}: "
read -r HTTP_PORT
HTTP_PORT=${HTTP_PORT:-$DEFAULT_HTTP_PORT}
if ! is_valid_port "$HTTP_PORT"; then
    error "Invalid HTTP port: $HTTP_PORT"
    exit 1
fi

echo -e -n "${CYAN}▸${NC} HTTPS port ${DIM}(host port for nginx, default: ${DEFAULT_HTTPS_PORT})${NC}: "
read -r HTTPS_PORT
HTTPS_PORT=${HTTPS_PORT:-$DEFAULT_HTTPS_PORT}
if ! is_valid_port "$HTTPS_PORT"; then
    error "Invalid HTTPS port: $HTTPS_PORT"
    exit 1
fi
if [ "$HTTP_PORT" = "$HTTPS_PORT" ]; then
    error "HTTP and HTTPS ports must be different"
    exit 1
fi

if [ "$LOCAL_MODE" = false ] && { [ "$HTTP_PORT" != "80" ] || [ "$HTTPS_PORT" != "443" ]; }; then
    warn "Public mode with non-default host ports."
    info "Ensure your firewall/router forwards external TCP 80 → local TCP ${HTTP_PORT} and external TCP 443 → local TCP ${HTTPS_PORT}."
fi

# ── Create .env ──────────────────────────────────────────────────────────────

section "Setup"

PUBLIC_BASE="https://${DOMAIN}"
if [ "$HTTPS_PORT" != "443" ]; then
    PUBLIC_BASE="https://${DOMAIN}:${HTTPS_PORT}"
fi

cat > .env << EOF
# WARP SHARE - Generated $(date +%Y-%m-%d)
PUBLIC_BASE=${PUBLIC_BASE}
DOMAIN=${DOMAIN}
MEDIA_ROOT=${MEDIA_ROOT}
UPLOAD_TEMP=${UPLOAD_TEMP}
HTTP_PORT=${HTTP_PORT}
HTTPS_PORT=${HTTPS_PORT}
TZ=Europe/Vienna
LOCAL_MODE=${LOCAL_MODE}
TEMP_CLEANUP_INTERVAL=6h
TEMP_CLEANUP_AGE=24h
EOF
[ -n "$EMAIL" ] && echo "CERTBOT_EMAIL=${EMAIL}" >> .env
success "Created .env"

# ── Configure nginx ──────────────────────────────────────────────────────────

if [ ! -f nginx/nginx.conf.template ]; then
    cp nginx/nginx.conf nginx/nginx.conf.template
fi

sed "s/{{DOMAIN}}/${DOMAIN}/g" nginx/nginx.conf.template > nginx/nginx.conf

if [ "$LOCAL_MODE" = true ]; then
    sed -i 's/ssl_stapling on;/# ssl_stapling on;  # Disabled for local mode/' nginx/nginx.conf
    sed -i 's/ssl_stapling_verify on;/# ssl_stapling_verify on;  # Disabled for local mode/' nginx/nginx.conf
fi

mkdir -p "$UPLOAD_TEMP"
mkdir -p "${MEDIA_ROOT}/media/share"
success "Configured nginx"

# ── SSL Certificate ──────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CERT_DIR="${SCRIPT_DIR}/certbot_data/live/${DOMAIN}"
CERT_PATH="${CERT_DIR}/fullchain.pem"

if [ -f "$CERT_PATH" ]; then
    success "SSL certificate exists"
else
    if [ "$LOCAL_MODE" = true ]; then
        info "Creating self-signed certificate (365 days)..."
        mkdir -p "$CERT_DIR"
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout "${CERT_DIR}/privkey.pem" \
            -out "${CERT_DIR}/fullchain.pem" \
            -subj "/CN=${DOMAIN}" \
            -addext "subjectAltName=DNS:${DOMAIN},IP:${DOMAIN}" 2>/dev/null || \
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout "${CERT_DIR}/privkey.pem" \
            -out "${CERT_DIR}/fullchain.pem" \
            -subj "/CN=${DOMAIN}" 2>/dev/null
        success "Self-signed certificate created"
    else
        info "Creating temporary certificate..."
        mkdir -p "$CERT_DIR"
        openssl req -x509 -nodes -days 1 -newkey rsa:2048 \
            -keyout "${CERT_DIR}/privkey.pem" \
            -out "${CERT_DIR}/fullchain.pem" \
            -subj "/CN=${DOMAIN}" 2>/dev/null
        success "Temporary certificate created"

        # DNS check (IPv4 + IPv6)
        SERVER_IP=$(curl -s -4 --max-time 4 ifconfig.me 2>/dev/null)
        DOMAIN_IP=$(dig +short "$DOMAIN" A 2>/dev/null | head -1)
        if [ -n "$SERVER_IP" ] && [ -n "$DOMAIN_IP" ] && [ "$SERVER_IP" != "$DOMAIN_IP" ]; then
            warn "DNS mismatch (IPv4): $DOMAIN → $DOMAIN_IP (server: $SERVER_IP)"
            echo -e -n "${YELLOW}▸${NC} Continue anyway? (y/N): "
            read -r response
            [[ ! "$response" =~ ^[Yy]$ ]] && exit 1
        fi

        SERVER_IP6=$(curl -s -6 --max-time 4 ifconfig.me 2>/dev/null)
        DOMAIN_IP6=$(dig +short "$DOMAIN" AAAA 2>/dev/null | head -1)
        if [ -n "$SERVER_IP6" ] && [ -z "$DOMAIN_IP6" ]; then
            warn "No AAAA record found for $DOMAIN (IPv6 available on server: $SERVER_IP6)"
        elif [ -n "$SERVER_IP6" ] && [ -n "$DOMAIN_IP6" ] && [ "$SERVER_IP6" != "$DOMAIN_IP6" ]; then
            warn "DNS mismatch (IPv6): $DOMAIN → $DOMAIN_IP6 (server: $SERVER_IP6)"
        fi
    fi
fi

# ── Build containers ─────────────────────────────────────────────────────────

info "Building containers..."
$DOCKER_COMPOSE build -q
success "Built containers"

# ── Request Let's Encrypt certificate ────────────────────────────────────────

if [ "$LOCAL_MODE" = true ]; then
    success "Using self-signed certificate"
elif ! openssl x509 -in "$CERT_PATH" -noout -issuer 2>/dev/null | grep -q "Let's Encrypt"; then
    info "Starting nginx for ACME challenge..."
    $DOCKER_COMPOSE up -d nginx
    sleep 5

    if ! $DOCKER_COMPOSE ps nginx 2>/dev/null | grep -q "Up"; then
        warn "nginx did not start cleanly. If ports ${HTTP_PORT}/${HTTPS_PORT} are already in use, ACME will fail."
        info "Check: docker compose ps && docker compose logs nginx"
    fi

    info "Preparing for Certbot..."
    rm -rf "${SCRIPT_DIR}/certbot_data/live/${DOMAIN}"
    rm -rf "${SCRIPT_DIR}/certbot_data/archive/${DOMAIN}"
    rm -rf "${SCRIPT_DIR}/certbot_data/renewal/${DOMAIN}.conf"

    info "Requesting Let's Encrypt certificate..."
    CERTBOT_ARGS="certonly --webroot -w /var/www/certbot -d $DOMAIN"
    if [ "${INCLUDE_WWW:-false}" = true ]; then
        CERTBOT_ARGS="$CERTBOT_ARGS -d www.$DOMAIN"
    fi
    CERTBOT_ARGS="$CERTBOT_ARGS --agree-tos --no-eff-email --non-interactive"
    [ -n "$EMAIL" ] && CERTBOT_ARGS="$CERTBOT_ARGS --email $EMAIL" || CERTBOT_ARGS="$CERTBOT_ARGS --register-unsafely-without-email"

    # NAT / port-forwarding hint (best-effort)
    LOCAL_IP4=$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if ($i=="src") {print $(i+1); exit}}')
    if [ -n "$LOCAL_IP4" ] && is_private_ipv4 "$LOCAL_IP4"; then
        warn "This host appears to be behind NAT (local IPv4: $LOCAL_IP4)."
        info "If you're running this at home, you likely need router port-forwarding: external TCP 80 → local TCP ${HTTP_PORT} and external TCP 443 → local TCP ${HTTPS_PORT}."
    fi

    if $DOCKER_COMPOSE run --rm --entrypoint certbot certbot $CERTBOT_ARGS; then
        success "SSL certificate obtained"
        $DOCKER_COMPOSE exec -T nginx nginx -s reload 2>/dev/null || $DOCKER_COMPOSE restart nginx
    else
        warn "Could not obtain Let's Encrypt certificate"
        info "Most common causes in Public mode:"
        echo -e "  ${DIM}- DNS not pointing to this server (A/AAAA wrong)${NC}"
        echo -e "  ${DIM}- Ports 80/443 blocked by firewall / security group${NC}"
        echo -e "  ${DIM}- Behind NAT without port-forwarding (home router)${NC}"
        echo -e "  ${DIM}- ISP blocks inbound 80/443${NC}"
        info "Try: ensure $DOMAIN resolves to this server and that inbound TCP 80 works (ACME uses HTTP-01)."
        info "Restoring temporary certificate..."
        mkdir -p "$CERT_DIR"
        openssl req -x509 -nodes -days 1 -newkey rsa:2048 \
            -keyout "${CERT_DIR}/privkey.pem" \
            -out "${CERT_DIR}/fullchain.pem" \
            -subj "/CN=${DOMAIN}" 2>/dev/null
    fi
fi

# ── Start Services ───────────────────────────────────────────────────────────

info "Starting services..."
$DOCKER_COMPOSE up -d

info "Waiting for warp-share..."
for i in {1..30}; do
    if docker logs warp-share 2>&1 | grep -q "listening on"; then
        break
    fi
    sleep 1
done
success "Services running"

# ── Show Results ─────────────────────────────────────────────────────────────

ADMIN_PATH=$(docker exec warp-share sh -c 'cat /data/admin_path 2>/dev/null' | tr -d '\r' | head -1)
if [ -z "$ADMIN_PATH" ]; then
    ADMIN_PATH=$(docker logs warp-share 2>&1 | grep -oP '(Your admin path: |ADMIN_PATH.*: |admin at )\K/[A-Za-z0-9_-]+' | head -1)
fi
ADMIN_PASS=$(docker exec warp-share sh -c 'cat /data/bootstrap_admin_password 2>/dev/null' | tr -d '\r' | head -1)

echo -e "\n${GREEN}══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}                       Setup Complete${NC}"
echo -e "${GREEN}══════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  ${DIM}URL${NC}     ${PUBLIC_BASE}"
[ -n "$ADMIN_PATH" ] && echo -e "  ${DIM}Admin${NC}   ${PUBLIC_BASE}${ADMIN_PATH}/"
echo ""
if [ "$LOCAL_MODE" = true ]; then
    echo -e "  ${YELLOW}ℹ${NC}  ${DIM}Local mode: Browser will show certificate warning${NC}"
fi
if [ -n "$ADMIN_PASS" ]; then
    echo -e "  ${YELLOW}🔑 Password: ${ADMIN_PASS}${NC}"
    echo -e "  ${DIM}   Stored in /data/bootstrap_admin_password.${NC}"

    if [ -t 0 ]; then
        echo -e -n "${CYAN}▸${NC} Delete /data/bootstrap_admin_password now? ${DIM}[Y/n]${NC}: "
        read -r DEL_PASSFILE
        if [[ -z "$DEL_PASSFILE" || "$DEL_PASSFILE" =~ ^[Yy]$ ]]; then
            if docker exec warp-share sh -c 'rm -f /data/bootstrap_admin_password' >/dev/null 2>&1; then
                echo -e "  ${GREEN}✓${NC} ${DIM}Deleted /data/bootstrap_admin_password${NC}"
            else
                echo -e "  ${YELLOW}⚠${NC} ${DIM}Could not delete /data/bootstrap_admin_password (delete it manually after login).${NC}"
            fi
        fi
    fi
else
    echo -e "  ${DIM}ℹ  Existing install – password unchanged${NC}"
fi
echo ""
