#!/usr/bin/env bash
# ==============================================================================
#  MailOpen - Autonomous Self-Hosted Mail Server Control Plane
#  One-Line Interactive & Automated Production Installer
#  Repository: https://github.com/azdharsyahputra/opemail
# ==============================================================================

set -eo pipefail

INSTALL_DIR="/opt/openmail"
REPO_URL="https://github.com/azdharsyahputra/opemail.git"

# Colors & Formatting
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

info() {
    printf "${CYAN}[INFO]${NC} %s\n" "$1"
}

success() {
    printf "${GREEN}[✓]${NC} %s\n" "$1"
}

warn() {
    printf "${YELLOW}[!]${NC} %s\n" "$1"
}

error() {
    printf "${RED}[ERROR]${NC} %s\n" "$1" >&2
}

prompt_read() {
    local prompt_msg="$1"
    local var_name="$2"
    local default_val="$3"

    local input_val=""
    if [ -e /dev/tty ]; then
        printf "%b" "$prompt_msg" > /dev/tty
        read -r input_val < /dev/tty || true
    else
        printf "%b" "$prompt_msg"
        read -r input_val || true
    fi

    if [ -z "$input_val" ]; then
        eval "$var_name=\"$default_val\""
    else
        eval "$var_name=\"$input_val\""
    fi
}

banner() {
    clear 2>/dev/null || true
    printf "${BOLD}${CYAN}"
    cat << "BANNER"
  __  __       _ _  ____                  
 |  \/  | __ _(_) |/ __ \                 
 | \  / |/ _` | | | |  | |_ __   ___ _ __  
 | |\/| | (_| | | | |  | | '_ \ / _ \ '_ \ 
 | |  | |\__,_|_|_| |__| | |_) |  __/ | | |
 |_|  |_|          \____/| .__/ \___|_| |_|
                         | |               
                         |_|               
BANNER
    printf "${NC}"
    printf "${BOLD}MailOpen Automated Production Installer${NC}\n"
    printf "Standard-compliant, Zero-Trust Enterprise Mail Engine\n"
    printf "=======================================================\n\n"
}

# Pre-flight Check: Operating System
check_os() {
    OS="$(uname -s)"
    case "${OS}" in
        Linux*)     MACHINE="Linux";;
        Darwin*)    MACHINE="Mac";;
        *)          MACHINE="UNKNOWN:${OS}"
    esac

    if [ "$MACHINE" != "Linux" ] && [ "$MACHINE" != "Mac" ]; then
        error "Unsupported operating system: $OS. OpenMail requires Linux or macOS."
        exit 1
    fi
    success "Operating System: $MACHINE"
}

# Pre-flight Check: Tools & Git
check_prerequisites() {
    if ! command -v git >/dev/null 2>&1 || ! command -v curl >/dev/null 2>&1 || ! command -v openssl >/dev/null 2>&1; then
        info "Installing core prerequisites (git, curl, openssl)..."
        if [ "$MACHINE" = "Linux" ]; then
            if command -v apt-get >/dev/null 2>&1; then
                apt-get update -qq && apt-get install -y -qq git curl openssl
            elif command -v dnf >/dev/null 2>&1; then
                dnf install -y git curl openssl
            elif command -v yum >/dev/null 2>&1; then
                yum install -y git curl openssl
            fi
        fi
    fi
    success "Prerequisites (git, curl, openssl) verified."
}

# Pre-flight Check: Docker & Compose
check_docker() {
    if ! command -v docker >/dev/null 2>&1; then
        info "Docker is not detected. Automatically installing official Docker engine..."
        if [ "$MACHINE" = "Linux" ]; then
            curl -fsSL https://get.docker.com | sh
            systemctl start docker || true
            systemctl enable docker || true
            success "Docker installed successfully!"
        else
            error "Docker Desktop is required on macOS. Please install and start Docker Desktop."
            exit 1
        fi
    fi

    if ! docker compose version >/dev/null 2>&1; then
        info "Installing Docker Compose plugin..."
        if [ "$MACHINE" = "Linux" ]; then
            if command -v apt-get >/dev/null 2>&1; then
                apt-get update -qq && apt-get install -y -qq docker-compose-plugin || true
            elif command -v dnf >/dev/null 2>&1; then
                dnf install -y docker-compose-plugin || true
            elif command -v yum >/dev/null 2>&1; then
                yum install -y docker-compose-plugin || true
            fi
        fi
    fi

    if ! docker info >/dev/null 2>&1; then
        error "Docker daemon is not running. Please start Docker service: sudo systemctl start docker"
        exit 1
    fi
    success "Docker & Docker Compose detected and running."
}

# Port Conflict Diagnostics
check_ports() {
    info "Scanning standard mail ports (25, 587, 143, 993, 3000, 8085)..."
    local ports=(25 587 143 993 3000 8085)
    for p in "${ports[@]}"; do
        if command -v lsof >/dev/null 2>&1; then
            if lsof -Pi :"$p" -sTCP:LISTEN -t >/dev/null 2>&1; then
                warn "Port $p is currently in use by another process on the host."
                if [ "$p" -eq 25 ] && [ "$MACHINE" = "Linux" ]; then
                    info "Disabling conflicting host mail services (postfix/exim4)..."
                    systemctl stop postfix exim4 2>/dev/null || true
                    systemctl disable postfix exim4 2>/dev/null || true
                fi
            fi
        fi
    done
}

# Setup installation directory & clone codebase
setup_codebase() {
    if [ ! -f "docker-compose.yml" ] || [ ! -f "Dockerfile" ]; then
        info "Setting up installation directory at ${INSTALL_DIR}..."
        mkdir -p "${INSTALL_DIR}"
        cd "${INSTALL_DIR}"

        if [ -d ".git" ]; then
            info "Updating existing repository in ${INSTALL_DIR}..."
            git pull -q origin main || true
        else
            info "Cloning OpenMail repository..."
            git clone -q "${REPO_URL}" .
        fi
    fi
    success "Working directory ready: $(pwd)"
}

# Prompt user for installation configuration
gather_config() {
    info "Detecting public WAN IPv4..."
    SERVER_IP=$(curl -s --max-time 3 https://api.ipify.org || curl -s --max-time 3 https://ifconfig.me || echo "127.0.0.1")
    success "Detected Public WAN IP: $SERVER_IP"

    echo ""
    printf "${BOLD}Please configure your primary mail server settings:${NC}\n"
    printf "---------------------------------------------------\n"

    # Domain
    if [ -z "$DOMAIN" ]; then
        while [ -z "$DOMAIN" ]; do
            prompt_read "1. Primary Virtual Domain (e.g. example.com): " DOMAIN ""
            if [ -z "$DOMAIN" ]; then
                printf "${RED}Domain cannot be empty.${NC}\n"
            fi
        done
    fi

    # Hostname FQDN
    if [ -z "$MAIL_HOSTNAME" ]; then
        DEFAULT_HOSTNAME="mail.${DOMAIN}"
        prompt_read "2. Mail Server Hostname (default: ${DEFAULT_HOSTNAME}): " MAIL_HOSTNAME "$DEFAULT_HOSTNAME"
    fi

    # Admin Email
    if [ -z "$ADMIN_EMAIL" ]; then
        DEFAULT_ADMIN="admin@${DOMAIN}"
        prompt_read "3. Admin Account Email (default: ${DEFAULT_ADMIN}): " ADMIN_EMAIL "$DEFAULT_ADMIN"
    fi

    # Admin Password
    if [ -z "$ADMIN_PASSWORD" ]; then
        DEFAULT_PASS=$(openssl rand -base64 12 | tr -dc 'a-zA-Z0-9' | head -c 14)
        DEFAULT_PASS="${DEFAULT_PASS}!"
        prompt_read "4. Admin Password (leave blank for auto-generated: ${DEFAULT_PASS}): " ADMIN_PASSWORD "$DEFAULT_PASS"
    fi

    # Panel Port
    if [ -z "$PANEL_PORT" ]; then
        prompt_read "5. Web Panel HTTP Port (default: 3000): " PANEL_PORT "3000"
    fi

    # API Port
    if [ -z "$API_PORT" ]; then
        API_PORT=8085
    fi
}

# Generate Secure Secrets & .env
setup_environment() {
    info "Generating cryptographically secure secrets and configuration..."

    PG_PASS=$(openssl rand -hex 16)
    JWT_SEC=$(openssl rand -hex 32)

    cat << ENVFILE > .env
# Auto-generated by OpenMail Installer on $(date -u)
POSTGRES_USER=mailopen
POSTGRES_PASSWORD=${PG_PASS}
POSTGRES_DB=mailopen
POSTGRES_PORT=5433

DATABASE_URL=postgres://mailopen:${PG_PASS}@postgres:5432/mailopen?sslmode=disable
JWT_SECRET=${JWT_SEC}

POSTFIX_HOSTNAME=${MAIL_HOSTNAME}
TLSHOSTNAME=${MAIL_HOSTNAME}

PANEL_PORT=${PANEL_PORT}
API_PORT=${API_PORT}

VMAIL_ROOT=/var/vmail
VMAIL_DIR=/var/vmail
STORAGE_PATH=/var/mailopen/blobs
TLS_BASE_DIR=/etc/mailopen/tls
DKIM_BASE_DIR=/etc/mailopen/dkim
ENVFILE

    chmod 0600 .env
    success "Configuration written to .env"

    # Setup directories
    mkdir -p data/vmail data/postfix data/dovecot data/tls/${MAIL_HOSTNAME} data/dkim data/opendkim data/blobs
    chmod 0750 data/vmail

    # Generate fallback TLS certificate if not exists
    if [ ! -f "data/tls/${MAIL_HOSTNAME}/fullchain.pem" ]; then
        info "Generating initial fallback TLS certificate for ${MAIL_HOSTNAME}..."
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout "data/tls/${MAIL_HOSTNAME}/privkey.pem" \
            -out "data/tls/${MAIL_HOSTNAME}/fullchain.pem" \
            -subj "/CN=${MAIL_HOSTNAME}" >/dev/null 2>&1
        success "Fallback TLS certificate generated."
    fi
}

# Deploy & Provision Stack
deploy_cluster() {
    info "Building and launching OpenMail service cluster..."
    docker compose up -d --build

    info "Waiting for PostgreSQL database to be healthy..."
    local retries=30
    while [ $retries -gt 0 ]; do
        if docker compose exec -T postgres pg_isready -U mailopen -d mailopen >/dev/null 2>&1; then
            break
        fi
        sleep 1
        retries=$((retries - 1))
    done

    if [ $retries -eq 0 ]; then
        error "PostgreSQL container failed to become healthy."
        exit 1
    fi
    success "Database is ready."

    info "Creating internal daemon database roles..."
    docker compose exec -T postgres psql -U mailopen -d mailopen -c "
    DO \$\$
    BEGIN
       IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'mailopen_postfix') THEN
          CREATE ROLE mailopen_postfix WITH LOGIN PASSWORD 'postfix_secret';
       END IF;
       IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'mailopen_dovecot') THEN
          CREATE ROLE mailopen_dovecot WITH LOGIN PASSWORD 'dovecot_secret';
       END IF;
    END \$\$;
    GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO mailopen_postfix, mailopen_dovecot;
    " >/dev/null 2>&1 || true

    info "Applying database schema migrations..."
    docker compose exec -T backend mailopen migrate up >/dev/null 2>&1 || true

    info "Generating Postfix and Dovecot atomic daemon maps..."
    docker compose exec -T backend mailopen postfix config generate --out-dir /data/postfix --target-path /etc/postfix >/dev/null 2>&1 || true
    docker compose exec -T backend mailopen dovecot config generate --out-dir /data/dovecot --target-path /etc/dovecot >/dev/null 2>&1 || true

    info "Restarting Postfix MTA and Dovecot IMAP with new configuration..."
    docker compose restart postfix dovecot >/dev/null 2>&1

    info "Bootstrapping primary domain '${DOMAIN}' and admin account '${ADMIN_EMAIL}'..."
    docker compose exec -T backend mailopen domain create "${DOMAIN}" >/dev/null 2>&1 || true
    docker compose exec -T backend mailopen mailbox create "${ADMIN_EMAIL}" --password "${ADMIN_PASSWORD}" --role admin --quota 10240 >/dev/null 2>&1 || true

    success "Cluster deployment & provisioning complete!"
}

# Display Installation Summary
show_summary() {
    printf "\n"
    printf "${GREEN}${BOLD}=======================================================${NC}\n"
    printf "${GREEN}${BOLD}       🎉 MAILOPEN DEPLOYED SUCCESSFULLY!              ${NC}\n"
    printf "${GREEN}${BOLD}=======================================================${NC}\n\n"

    printf "${BOLD}1. Web Control Panel:${NC}\n"
    printf "   URL           : ${CYAN}http://${SERVER_IP}:${PANEL_PORT}${NC} (or http://localhost:${PANEL_PORT})\n"
    printf "   Admin User    : ${BOLD}%s${NC}\n" "${ADMIN_EMAIL}"
    printf "   Admin Password: ${YELLOW}%s${NC}\n\n" "${ADMIN_PASSWORD}"

    printf "${BOLD}2. Mail Service Endpoints:${NC}\n"
    printf "   SMTP (Inbound): %s:25\n" "${SERVER_IP}"
    printf "   SMTP (Submit) : %s:587 (STARTTLS)\n" "${SERVER_IP}"
    printf "   IMAP (Secure) : %s:143 (STARTTLS) / %s:993 (SSL/TLS)\n" "${SERVER_IP}" "${SERVER_IP}"
    printf "   REST API Docs : http://%s:%s/health/live\n" "${SERVER_IP}" "${API_PORT}"
    printf "   Prometheus    : http://%s:%s/metrics\n\n" "${SERVER_IP}" "${API_PORT}"

    printf "${BOLD}3. Recommended Next Steps:${NC}\n"
    printf "   1. Open the Web Panel at ${CYAN}http://%s:%s${NC}\n" "${SERVER_IP}" "${PANEL_PORT}"
    printf "   2. Go to ${BOLD}Domains & DNS${NC} to view your Cloudflare DNS records (MX, SPF, DKIM, DMARC).\n"
    printf "   3. Add DNS records to your DNS provider to begin receiving external emails.\n\n"

    printf "Manage cluster anytime with: ${BOLD}cd /opt/openmail && docker compose [ps|logs|restart|down]${NC}\n\n"
}

# Main Execution Flow
main() {
    banner
    check_os
    check_prerequisites
    check_docker
    check_ports
    setup_codebase
    gather_config
    setup_environment
    deploy_cluster
    show_summary
}

main "$@"
