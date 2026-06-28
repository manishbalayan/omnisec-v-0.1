#!/bin/sh
# =============================================================================
# OmniSec — Host-Native Installer
# =============================================================================
# Installs OmniSec as professional infrastructure software — no Docker, no
# containers. Everything runs directly on the host as native services
# (systemd on Linux, launchd on macOS).
#
#   curl -fsSL https://raw.githubusercontent.com/manishbalayan/omnisec-v-0.1/main/deploy/install.sh | sudo sh
#
# Flow:
#   detect OS/arch -> create service user -> create directories ->
#   install PostgreSQL + NATS (native) -> download OmniSec binaries + dashboard ->
#   install launchers + config -> initialize database -> register services ->
#   start services in order -> verify each -> done.
#
# Flags:
#   --uninstall        Remove all OmniSec services, binaries, and data.
#   --version <tag>    Install a specific release tag.
#   --build            Build binaries from source (requires cargo + node).
#
# Fully POSIX (sh/dash/bash/zsh). Requires root (run with sudo).
# =============================================================================

set -eu

# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------
REPO_OWNER="${GITHUB_REPO_OWNER:-manishbalayan}"
REPO_NAME="${GITHUB_REPO_NAME:-omnisec-v-0.1}"
RELEASE_TAG="${OMNISEC_VERSION:-v0.1.0}"
GH_RELEASES="https://github.com/${REPO_OWNER}/${REPO_NAME}/releases/download/${RELEASE_TAG}"
NATS_VERSION="${OMNISEC_NATS_VERSION:-2.10.21}"

DASHBOARD_PORT="${OMNISEC_DASHBOARD_PORT:-3000}"
API_PORT="${OMNISEC_API_PORT:-3002}"
DAEMON_HEALTH_PORT="${OMNISEC_DAEMON_HEALTH_PORT:-3003}"
POSTGRES_PORT="${OMNISEC_POSTGRES_PORT:-5432}"
NATS_PORT="${OMNISEC_NATS_PORT:-4222}"

INSTALL_BIN="/usr/local/bin"
LIBEXEC_DIR="/usr/local/libexec/omnisec"

DO_UNINSTALL=0
DO_BUILD=0

# Colors
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
info()    { printf "  ${BLUE}◆${NC} %s\n" "$1"; }
success() { printf "  ${GREEN}✓${NC} %s\n" "$1"; }
warn()    { printf "  ${YELLOW}⚠${NC} %s\n" "$1"; }
fail()    { printf "  ${RED}✗${NC} %s\n" "$1"; }
step()    { printf "\n━━━ %s ━━━\n" "$1"; }
has_cmd() { command -v "$1" >/dev/null 2>&1; }
die()     { fail "$1"; exit 1; }

# -----------------------------------------------------------------------------
# Argument parsing
# -----------------------------------------------------------------------------
while [ $# -gt 0 ]; do
    case "$1" in
        --uninstall) DO_UNINSTALL=1 ;;
        --build)     DO_BUILD=1 ;;
        --version)   shift; RELEASE_TAG="$1"; GH_RELEASES="https://github.com/${REPO_OWNER}/${REPO_NAME}/releases/download/${RELEASE_TAG}" ;;
        *) warn "Unknown argument: $1" ;;
    esac
    shift
done

# -----------------------------------------------------------------------------
# Platform detection (sets OS_KIND, ARCH, and per-OS path layout)
# -----------------------------------------------------------------------------
detect_platform() {
    OS_UNAME="$(uname -s)"
    ARCH_UNAME="$(uname -m)"

    case "${OS_UNAME}" in
        Linux)  OS_KIND="linux";  OS_TAG="linux" ;;
        Darwin) OS_KIND="macos";  OS_TAG="darwin" ;;
        *) die "Unsupported OS: ${OS_UNAME}. OmniSec requires Linux or macOS." ;;
    esac

    case "${ARCH_UNAME}" in
        x86_64|amd64)  ARCH="amd64" ;;
        aarch64|arm64) ARCH="arm64" ;;
        *) die "Unsupported architecture: ${ARCH_UNAME}" ;;
    esac

    if [ "${OS_KIND}" = "linux" ]; then
        CONFIG_DIR="/etc/omnisec"
        DATA_DIR="/var/lib/omnisec"
        LOG_DIR="/var/log/omnisec"
        RUN_DIR="/var/run/omnisec"
        DASH_DIR="/opt/omnisec/dashboard"
        SERVICE_USER="omnisec"
        NATS_OS="linux"
    else
        CONFIG_DIR="/usr/local/etc/omnisec"
        DATA_DIR="/usr/local/var/omnisec"
        LOG_DIR="/usr/local/var/log/omnisec"
        RUN_DIR="/usr/local/var/run/omnisec"
        DASH_DIR="/usr/local/opt/omnisec/dashboard"
        SERVICE_USER="_omnisec"
        NATS_OS="darwin"
    fi
    PGDATA="${DATA_DIR}/postgres"
    NATS_STORE="${DATA_DIR}/nats"
    CONFIG_ENV="${CONFIG_DIR}/omnisec.env"
}

require_root() {
    if [ "$(id -u)" != "0" ]; then
        die "OmniSec installer must run as root. Re-run with: sudo sh"
    fi
}

# Run a command as the OmniSec service user.
as_service_user() {
    if [ "${OS_KIND}" = "linux" ]; then
        su -s /bin/sh "${SERVICE_USER}" -c "$1"
    else
        sudo -u "${SERVICE_USER}" /bin/sh -c "$1"
    fi
}

# =============================================================================
# UNINSTALL
# =============================================================================
uninstall() {
    step "Uninstalling OmniSec"
    if [ "${OS_KIND}" = "linux" ]; then
        for svc in omnisec.target omnisec-dashboard omnisec-api omnisec-daemon omnisec-nats omnisec-postgres; do
            systemctl stop "${svc}" 2>/dev/null || true
            systemctl disable "${svc}" 2>/dev/null || true
        done
        rm -f /etc/systemd/system/omnisec-*.service /etc/systemd/system/omnisec.target
        systemctl daemon-reload 2>/dev/null || true
    else
        for lbl in dashboard api daemon nats postgres; do
            launchctl bootout "system/com.omnisec.${lbl}" 2>/dev/null || \
                launchctl unload "/Library/LaunchDaemons/com.omnisec.${lbl}.plist" 2>/dev/null || true
            rm -f "/Library/LaunchDaemons/com.omnisec.${lbl}.plist"
        done
    fi
    rm -f "${INSTALL_BIN}/omnisec-daemon" "${INSTALL_BIN}/omnisec-api" "${INSTALL_BIN}/omnisec-doctor"
    rm -rf "${LIBEXEC_DIR}"
    success "Services and binaries removed"
    warn "Data preserved at ${DATA_DIR} and config at ${CONFIG_DIR}"
    warn "To remove everything: sudo rm -rf ${DATA_DIR} ${CONFIG_DIR} ${LOG_DIR} /opt/omnisec"
    printf "\n"
    exit 0
}

# =============================================================================
# Service user + directories
# =============================================================================
create_service_user() {
    step "Service User"
    if [ "${OS_KIND}" = "linux" ]; then
        if id "${SERVICE_USER}" >/dev/null 2>&1; then
            success "User ${SERVICE_USER} exists"
        else
            useradd --system --no-create-home --shell /usr/sbin/nologin "${SERVICE_USER}" 2>/dev/null \
                || useradd --system --no-create-home --shell /bin/false "${SERVICE_USER}" 2>/dev/null \
                || adduser --system --no-create-home "${SERVICE_USER}" 2>/dev/null || true
            success "Created system user ${SERVICE_USER}"
        fi
    else
        if dscl . -read "/Users/${SERVICE_USER}" >/dev/null 2>&1; then
            success "User ${SERVICE_USER} exists"
        else
            # Pick a free UID in the system range
            _uid=450
            while dscl . -list /Users UniqueID 2>/dev/null | awk '{print $2}' | grep -q "^${_uid}$"; do
                _uid=$((_uid + 1))
            done
            dscl . -create "/Users/${SERVICE_USER}"
            dscl . -create "/Users/${SERVICE_USER}" UserShell /usr/bin/false
            dscl . -create "/Users/${SERVICE_USER}" RealName "OmniSec Service"
            dscl . -create "/Users/${SERVICE_USER}" UniqueID "${_uid}"
            dscl . -create "/Users/${SERVICE_USER}" PrimaryGroupID 20
            dscl . -create "/Users/${SERVICE_USER}" NFSHomeDirectory /var/empty
            success "Created service user ${SERVICE_USER} (uid ${_uid})"
        fi
    fi
}

create_directories() {
    step "Directories"
    for d in "${CONFIG_DIR}" "${DATA_DIR}" "${PGDATA}" "${NATS_STORE}" "${LOG_DIR}" "${RUN_DIR}" "${DASH_DIR}" "${LIBEXEC_DIR}"; do
        mkdir -p "$d"
    done
    # Service user owns data, logs, run dirs (daemon runs as root and can still write)
    chown -R "${SERVICE_USER}" "${DATA_DIR}" "${LOG_DIR}" "${RUN_DIR}" 2>/dev/null || true
    chmod 700 "${PGDATA}" 2>/dev/null || true
    success "Created ${CONFIG_DIR}, ${DATA_DIR}, ${LOG_DIR}, ${DASH_DIR}"
}

# =============================================================================
# PostgreSQL (native)
# =============================================================================
detect_pgbin() {
    # Find a directory containing both `postgres` and `initdb`.
    for cand in \
        "${OMNISEC_PGBIN:-}" \
        $(ls -d /usr/lib/postgresql/*/bin 2>/dev/null | sort -V | tail -1) \
        $(ls -d /usr/pgsql-*/bin 2>/dev/null | sort -V | tail -1) \
        /usr/local/opt/postgresql@16/bin /usr/local/opt/postgresql@15/bin /opt/homebrew/opt/postgresql@16/bin \
        /usr/local/bin /usr/bin /opt/homebrew/bin; do
        [ -n "$cand" ] || continue
        if [ -x "$cand/postgres" ] && [ -x "$cand/initdb" ]; then
            printf "%s" "$cand"; return 0
        fi
    done
    return 1
}

install_postgres() {
    step "PostgreSQL"
    if PGBIN=$(detect_pgbin); then
        success "PostgreSQL found at ${PGBIN}"
        return 0
    fi
    info "PostgreSQL not found — installing..."
    if [ "${OS_KIND}" = "linux" ]; then
        if has_cmd apt-get; then
            apt-get update -qq && apt-get install -y postgresql >/dev/null
        elif has_cmd dnf; then
            dnf install -y postgresql-server >/dev/null
        elif has_cmd yum; then
            yum install -y postgresql-server >/dev/null
        elif has_cmd pacman; then
            pacman -Sy --noconfirm postgresql >/dev/null
        elif has_cmd zypper; then
            zypper install -y postgresql-server >/dev/null
        else
            die "No supported package manager found. Install PostgreSQL manually and re-run."
        fi
    else
        has_cmd brew || die "Homebrew required on macOS. Install from https://brew.sh then re-run."
        as_service_user "brew install postgresql@16" 2>/dev/null || brew install postgresql@16 >/dev/null
    fi
    PGBIN=$(detect_pgbin) || die "PostgreSQL installation did not produce usable binaries."
    success "PostgreSQL installed at ${PGBIN}"
}

init_database() {
    step "Database Initialization"
    if [ -f "${PGDATA}/PG_VERSION" ]; then
        success "Database cluster already initialized"
    else
        info "Initializing cluster at ${PGDATA}..."
        chown "${SERVICE_USER}" "${PGDATA}"
        as_service_user "'${PGBIN}/initdb' -D '${PGDATA}' -U '${SERVICE_USER}' --auth-local=trust --auth-host=scram-sha-256 -E UTF8" >/dev/null
        # Configure: loopback only, fixed port, socket in RUN_DIR
        {
            printf "listen_addresses = '127.0.0.1'\n"
            printf "port = %s\n" "${POSTGRES_PORT}"
            printf "unix_socket_directories = '%s'\n" "${RUN_DIR}"
            printf "max_connections = 100\n"
            printf "shared_buffers = 128MB\n"
        } >> "${PGDATA}/postgresql.conf"
        printf "host all all 127.0.0.1/32 scram-sha-256\n" >> "${PGDATA}/pg_hba.conf"
        success "Cluster initialized (loopback, port ${POSTGRES_PORT})"
    fi
}

bootstrap_db_role() {
    # Start a temporary instance to create role + db, then it will be managed by the service.
    info "Creating omnisec role and database..."
    as_service_user "'${PGBIN}/pg_ctl' -D '${PGDATA}' -o '-p ${POSTGRES_PORT}' -w -t 60 start" >/dev/null 2>&1 || true
    # Wait for readiness
    i=0; while [ $i -lt 30 ]; do
        as_service_user "'${PGBIN}/pg_isready' -h 127.0.0.1 -p ${POSTGRES_PORT}" >/dev/null 2>&1 && break
        sleep 1; i=$((i + 1))
    done
    PSQL="'${PGBIN}/psql' -h 127.0.0.1 -p ${POSTGRES_PORT} -d postgres -tAc"
    # Role 'omnisec' already exists as the initdb superuser; just set a password.
    as_service_user "${PSQL} \"ALTER ROLE omnisec WITH LOGIN PASSWORD 'omnisec';\"" >/dev/null 2>&1 || true
    if ! as_service_user "${PSQL} \"SELECT 1 FROM pg_database WHERE datname='omnisec';\"" 2>/dev/null | grep -q 1; then
        as_service_user "'${PGBIN}/createdb' -h 127.0.0.1 -p ${POSTGRES_PORT} -O omnisec omnisec" >/dev/null 2>&1 || true
    fi
    as_service_user "'${PGBIN}/pg_ctl' -D '${PGDATA}' -w -t 30 stop" >/dev/null 2>&1 || true
    success "Database 'omnisec' ready"
}

# =============================================================================
# NATS (native)
# =============================================================================
install_nats() {
    step "NATS"
    if has_cmd nats-server; then
        success "nats-server found ($(nats-server --version 2>/dev/null | head -1))"
        return 0
    fi
    info "Installing nats-server ${NATS_VERSION}..."
    if [ "${OS_KIND}" = "macos" ] && has_cmd brew; then
        brew install nats-server >/dev/null && { success "nats-server installed via Homebrew"; return 0; }
    fi
    _tgz="nats-server-v${NATS_VERSION}-${NATS_OS}-${ARCH}.tar.gz"
    _url="https://github.com/nats-io/nats-server/releases/download/v${NATS_VERSION}/${_tgz}"
    _tmp=$(mktemp -d)
    if curl -fsSL "${_url}" -o "${_tmp}/nats.tgz" 2>/dev/null; then
        tar -xzf "${_tmp}/nats.tgz" -C "${_tmp}"
        _bin=$(find "${_tmp}" -name nats-server -type f | head -1)
        install -m 755 "${_bin}" "${INSTALL_BIN}/nats-server"
        rm -rf "${_tmp}"
        success "nats-server ${NATS_VERSION} installed to ${INSTALL_BIN}"
    else
        rm -rf "${_tmp}"
        die "Failed to download nats-server from ${_url}"
    fi
}

# =============================================================================
# OmniSec binaries + dashboard
# =============================================================================
# Portable in-place sed (GNU and BSD).
sed_inplace() {
    _expr="$1"; _file="$2"
    if sed --version >/dev/null 2>&1; then sed -i "${_expr}" "${_file}"; else sed -i '' "${_expr}" "${_file}"; fi
}

# The dashboard is a client-side app: NEXT_PUBLIC_* are baked into the browser
# bundle at build time, but the API key is generated at install time. CI builds
# the bundle with a placeholder key; we patch the real key in here (host-native
# equivalent of the old container entrypoint sed-patch).
ensure_api_key() {
    if [ -z "${OMNISEC_API_KEY:-}" ]; then
        if has_cmd openssl; then
            OMNISEC_API_KEY="omnisec-$(openssl rand -hex 24)"
        else
            OMNISEC_API_KEY="omnisec-$(head -c32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
        fi
    fi
}

patch_dashboard() {
    [ -d "${DASH_DIR}" ] || return 0
    info "Patching dashboard with API endpoint + key..."
    find "${DASH_DIR}" -type f \( -name '*.js' -o -name '*.html' -o -name '*.json' \) 2>/dev/null | while read -r f; do
        grep -q '__OMNISEC_API_KEY__\|omnisec-api-placeholder' "$f" 2>/dev/null || continue
        sed_inplace "s|__OMNISEC_API_KEY__|${OMNISEC_API_KEY}|g" "$f"
        sed_inplace "s|http://omnisec-api-placeholder:3002|http://127.0.0.1:${API_PORT}|g" "$f"
    done
}

build_from_source() {
    has_cmd cargo || die "--build requires cargo (https://rustup.rs)"
    has_cmd node || die "--build requires node"
    [ -f "Cargo.toml" ] || die "--build must run from the OmniSec repository root"
    info "Building Rust binaries (release)..."
    cargo build --release --bin omnisec-daemon --bin omnisec-api --bin omnisec-doctor
    install -m 755 target/release/omnisec-daemon "${INSTALL_BIN}/omnisec-daemon"
    install -m 755 target/release/omnisec-api    "${INSTALL_BIN}/omnisec-api"
    install -m 755 target/release/omnisec-doctor "${INSTALL_BIN}/omnisec-doctor"
    info "Building dashboard..."
    # Build with the real key directly (no placeholder patching needed).
    ( cd apps/dashboard && npm install --silent && \
        NEXT_PUBLIC_API_URL="http://127.0.0.1:${API_PORT}" \
        NEXT_PUBLIC_API_KEY="${OMNISEC_API_KEY}" npm run build )
    rm -rf "${DASH_DIR}"; mkdir -p "${DASH_DIR}"
    cp -R apps/dashboard/.next/standalone/. "${DASH_DIR}/"
    mkdir -p "${DASH_DIR}/.next"
    cp -R apps/dashboard/.next/static "${DASH_DIR}/.next/static"
    [ -d apps/dashboard/public ] && cp -R apps/dashboard/public "${DASH_DIR}/public" || true
    success "Built binaries and dashboard from source"
}

download_artifacts() {
    step "OmniSec Binaries"
    if [ "${DO_BUILD}" = "1" ]; then
        build_from_source
        return 0
    fi
    _tmp=$(mktemp -d)
    for b in omnisec-daemon omnisec-api omnisec-doctor; do
        _url="${GH_RELEASES}/${b}-${OS_TAG}-${ARCH}"
        info "Downloading ${b}..."
        if ! curl -fsSL "${_url}" -o "${_tmp}/${b}" 2>/dev/null; then
            rm -rf "${_tmp}"
            warn "Could not download ${b} for ${OS_TAG}/${ARCH} from ${RELEASE_TAG}."
            warn "Build from source instead: clone the repo and run 'sudo sh deploy/install.sh --build'"
            die "Missing release artifact: ${b}-${OS_TAG}-${ARCH}"
        fi
        install -m 755 "${_tmp}/${b}" "${INSTALL_BIN}/${b}"
    done
    success "Installed omnisec-daemon, omnisec-api, omnisec-doctor to ${INSTALL_BIN}"

    info "Downloading dashboard bundle..."
    if curl -fsSL "${GH_RELEASES}/omnisec-dashboard.tar.gz" -o "${_tmp}/dash.tgz" 2>/dev/null; then
        rm -rf "${DASH_DIR}"; mkdir -p "${DASH_DIR}"
        tar -xzf "${_tmp}/dash.tgz" -C "${DASH_DIR}"
        patch_dashboard
        success "Dashboard installed to ${DASH_DIR}"
    else
        warn "Dashboard bundle not found in release — dashboard service will be skipped"
        SKIP_DASHBOARD=1
    fi
    rm -rf "${_tmp}"
    chown -R "${SERVICE_USER}" "${DASH_DIR}" 2>/dev/null || true
}

# =============================================================================
# Launchers + config
# =============================================================================
install_launchers() {
    step "Service Launchers + Configuration"
    # Resolve the directory this script's payload lives in (repo deploy/ or download).
    _src=""
    if [ -d "deploy/libexec" ]; then
        _src="deploy"
    else
        # Fetch launchers + service files from the repo when piped via curl.
        _src=$(mktemp -d)
        info "Fetching service definitions..."
        _base="https://raw.githubusercontent.com/${REPO_OWNER}/${REPO_NAME}/main/deploy"
        mkdir -p "${_src}/libexec" "${_src}/systemd" "${_src}/launchd"
        for f in omnisec-env.sh omnisec-postgres-run omnisec-nats-run omnisec-daemon-run omnisec-api-run omnisec-dashboard-run; do
            curl -fsSL "${_base}/libexec/${f}" -o "${_src}/libexec/${f}" || die "Failed to fetch launcher ${f}"
        done
        for f in omnisec-postgres omnisec-nats omnisec-daemon omnisec-api omnisec-dashboard; do
            curl -fsSL "${_base}/systemd/${f}.service" -o "${_src}/systemd/${f}.service" 2>/dev/null || true
        done
        curl -fsSL "${_base}/systemd/omnisec.target" -o "${_src}/systemd/omnisec.target" 2>/dev/null || true
        for f in postgres nats daemon api dashboard; do
            curl -fsSL "${_base}/launchd/com.omnisec.${f}.plist" -o "${_src}/launchd/com.omnisec.${f}.plist" 2>/dev/null || true
        done
        curl -fsSL "${_base}/omnisec.env" -o "${_src}/omnisec.env" 2>/dev/null || true
    fi
    SRC_DIR="${_src}"

    # Install launchers
    for f in omnisec-env.sh omnisec-postgres-run omnisec-nats-run omnisec-daemon-run omnisec-api-run omnisec-dashboard-run; do
        install -m 755 "${SRC_DIR}/libexec/${f}" "${LIBEXEC_DIR}/${f}"
    done
    success "Installed launchers to ${LIBEXEC_DIR}"

    # Render config env with per-OS paths. API key was set by ensure_api_key().
    ensure_api_key
    cat > "${CONFIG_ENV}" <<ENVEOF
# OmniSec configuration — generated by the installer. Sourced by service launchers.
DATABASE_URL=postgres://omnisec:omnisec@127.0.0.1:${POSTGRES_PORT}/omnisec
NATS_URL=nats://127.0.0.1:${NATS_PORT}
API_BIND=127.0.0.1:${API_PORT}
DAEMON_HEALTH_BIND=127.0.0.1:${DAEMON_HEALTH_PORT}
DASHBOARD_PORT=${DASHBOARD_PORT}
NATS_PORT=${NATS_PORT}
OMNISEC_PGDATA=${PGDATA}
OMNISEC_NATS_STORE=${NATS_STORE}
OMNISEC_PGBIN=${PGBIN}
OMNISEC_DASHBOARD_DIR=${DASH_DIR}
NEXT_PUBLIC_API_URL=http://127.0.0.1:${API_PORT}
OMNISEC_SAFE_MODE=0
OMNISEC_RECOMMENDATION_ONLY=0
OMNISEC_API_KEY=${OMNISEC_API_KEY}
RUST_LOG=info
ENVEOF
    chmod 640 "${CONFIG_ENV}"
    chown root:"$(id -gn ${SERVICE_USER} 2>/dev/null || echo ${SERVICE_USER})" "${CONFIG_ENV}" 2>/dev/null || true
    success "Wrote ${CONFIG_ENV}"
}

# =============================================================================
# Register + start services
# =============================================================================
register_services_linux() {
    step "Registering systemd services"
    for f in omnisec-postgres omnisec-nats omnisec-daemon omnisec-api omnisec-dashboard; do
        [ -f "${SRC_DIR}/systemd/${f}.service" ] && install -m 644 "${SRC_DIR}/systemd/${f}.service" "/etc/systemd/system/${f}.service"
    done
    install -m 644 "${SRC_DIR}/systemd/omnisec.target" /etc/systemd/system/omnisec.target 2>/dev/null || true
    systemctl daemon-reload
    systemctl enable omnisec-postgres omnisec-nats omnisec-daemon omnisec-api >/dev/null 2>&1 || true
    [ "${SKIP_DASHBOARD:-0}" = "1" ] || systemctl enable omnisec-dashboard >/dev/null 2>&1 || true
    systemctl enable omnisec.target >/dev/null 2>&1 || true

    info "Starting services in order..."
    systemctl start omnisec-postgres; sleep 2
    systemctl start omnisec-nats; sleep 1
    systemctl start omnisec-daemon
    systemctl start omnisec-api
    [ "${SKIP_DASHBOARD:-0}" = "1" ] || systemctl start omnisec-dashboard
    success "systemd services started"
}

register_services_macos() {
    step "Registering launchd services"
    for f in postgres nats daemon api dashboard; do
        [ "${f}" = "dashboard" ] && [ "${SKIP_DASHBOARD:-0}" = "1" ] && continue
        install -m 644 "${SRC_DIR}/launchd/com.omnisec.${f}.plist" "/Library/LaunchDaemons/com.omnisec.${f}.plist"
    done
    info "Bootstrapping services in order..."
    for f in postgres nats daemon api dashboard; do
        [ "${f}" = "dashboard" ] && [ "${SKIP_DASHBOARD:-0}" = "1" ] && continue
        _plist="/Library/LaunchDaemons/com.omnisec.${f}.plist"
        launchctl bootstrap system "${_plist}" 2>/dev/null || launchctl load -w "${_plist}" 2>/dev/null || true
        [ "${f}" = "postgres" ] && sleep 2
    done
    success "launchd services started"
}

# =============================================================================
# Verification
# =============================================================================
verify() {
    step "Verification"
    OK=true

    # PostgreSQL
    i=0; pg_ok=false
    while [ $i -lt 30 ]; do
        if as_service_user "'${PGBIN}/pg_isready' -h 127.0.0.1 -p ${POSTGRES_PORT}" >/dev/null 2>&1; then pg_ok=true; break; fi
        sleep 1; i=$((i + 1))
    done
    $pg_ok && success "PostgreSQL responding on 127.0.0.1:${POSTGRES_PORT}" || { fail "PostgreSQL not responding"; OK=false; }

    # NATS
    i=0; nats_ok=false
    while [ $i -lt 15 ]; do
        if curl -fsS "http://127.0.0.1:8222/healthz" >/dev/null 2>&1 || (exec 3<>"/dev/tcp/127.0.0.1/${NATS_PORT}") 2>/dev/null; then nats_ok=true; break; fi
        sleep 1; i=$((i + 1))
    done
    $nats_ok && success "NATS responding on 127.0.0.1:${NATS_PORT}" || warn "NATS health not confirmed (may still be starting)"

    # Daemon
    i=0; d_ok=false
    while [ $i -lt 30 ]; do
        if curl -fsS "http://127.0.0.1:${DAEMON_HEALTH_PORT}/health" >/dev/null 2>&1; then d_ok=true; break; fi
        sleep 1; i=$((i + 1))
    done
    $d_ok && success "Daemon health OK on 127.0.0.1:${DAEMON_HEALTH_PORT}" || { fail "Daemon health endpoint not responding"; OK=false; }

    # API
    i=0; a_ok=false
    while [ $i -lt 30 ]; do
        if curl -fsS "http://127.0.0.1:${API_PORT}/health" >/dev/null 2>&1; then a_ok=true; break; fi
        sleep 1; i=$((i + 1))
    done
    $a_ok && success "API health OK on 127.0.0.1:${API_PORT}" || { fail "API health endpoint not responding"; OK=false; }

    # Dashboard
    if [ "${SKIP_DASHBOARD:-0}" != "1" ]; then
        i=0; w_ok=false
        while [ $i -lt 30 ]; do
            if curl -fsS "http://127.0.0.1:${DASHBOARD_PORT}" >/dev/null 2>&1; then w_ok=true; break; fi
            sleep 1; i=$((i + 1))
        done
        $w_ok && success "Dashboard responding on 127.0.0.1:${DASHBOARD_PORT}" || warn "Dashboard not yet responding"
    fi

    [ "$OK" = "true" ] && return 0 || return 1
}

summary() {
    printf "\n"
    printf "╔═══════════════════════════════════════════════════════════════╗\n"
    if verify; then
        printf "║              OmniSec Installation Complete                    ║\n"
    else
        printf "║           OmniSec Installed (with warnings)                  ║\n"
    fi
    printf "╚═══════════════════════════════════════════════════════════════╝\n\n"
    printf "  Dashboard:  http://127.0.0.1:%s\n" "${DASHBOARD_PORT}"
    printf "  API:        http://127.0.0.1:%s\n" "${API_PORT}"
    printf "  API Key:    %s\n" "${OMNISEC_API_KEY}"
    printf "  Config:     %s\n\n" "${CONFIG_ENV}"
    if [ "${OS_KIND}" = "linux" ]; then
        printf "  Manage:     sudo systemctl status omnisec-daemon\n"
        printf "  Logs:       sudo journalctl -u omnisec-daemon -f\n"
        printf "  Stop all:   sudo systemctl stop omnisec.target\n"
    else
        printf "  Manage:     sudo launchctl print system/com.omnisec.daemon\n"
        printf "  Logs:       tail -f %s/daemon.log\n" "${LOG_DIR}"
    fi
    printf "  Doctor:     sudo omnisec-doctor\n"
    printf "  Uninstall:  sudo sh deploy/install.sh --uninstall\n\n"
}

# =============================================================================
# Main
# =============================================================================
printf "\n"
printf "╔═══════════════════════════════════════════════════════════════╗\n"
printf "║         OmniSec — Host-Native Installer (no Docker)          ║\n"
printf "╚═══════════════════════════════════════════════════════════════╝\n"

detect_platform
require_root
info "Platform: ${OS_TAG}/${ARCH}"

[ "${DO_UNINSTALL}" = "1" ] && uninstall

has_cmd curl || die "curl is required."

ensure_api_key
create_service_user
create_directories
install_postgres
install_nats
init_database
download_artifacts
install_launchers
bootstrap_db_role

if [ "${OS_KIND}" = "linux" ]; then
    register_services_linux
else
    register_services_macos
fi

summary
