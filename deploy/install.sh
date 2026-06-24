#!/bin/sh
# =============================================================================
# OmniSec One-Command Installer
# =============================================================================
# Fully POSIX-compatible — works with sh, dash, bash, zsh.
# Uses printf instead of echo -e for portable escape sequences,
# avoids arrays and bash-specific redirections.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/manishbalayan/omnisec-v-0.1/main/deploy/install.sh | sh
#
# What it does:
#   1. Detects OS and architecture
#   2. Checks prerequisites (curl, Docker)
#   3. Downloads correct daemon binary from GitHub Releases
#   4. Verifies SHA256 checksum
#   5. Installs daemon binary to /usr/local/bin/
#   6. Creates systemd service (Linux) or launchd plist (macOS)
#   7. Starts daemon
#   8. Starts Docker control plane stack
#   9. Verifies all services
#  10. Prints access URLs
#
# Requirements: curl, Docker
# No Rust/Cargo/compilation needed on the target machine.
# =============================================================================

set -eu

# =============================================================================
# Configuration
# =============================================================================
REPO_OWNER="${GITHUB_REPO_OWNER:-manishbalayan}"
REPO_NAME="${GITHUB_REPO_NAME:-omnisec-v-0.1}"
RELEASE_TAG="${OMNISEC_VERSION:-v0.1.0-daemon}"
GITHUB_RELEASES="https://github.com/${REPO_OWNER}/${REPO_NAME}/releases/download/${RELEASE_TAG}"

DEFAULT_DASHBOARD_PORT=3000
DEFAULT_API_PORT=3002
DEFAULT_DAEMON_HEALTH_PORT=3003
DEFAULT_POSTGRES_PORT=5432
DEFAULT_NATS_PORT=4222

INSTALL_DIR="/usr/local/bin"
DAEMON_BIN="${INSTALL_DIR}/omnisec-daemon"
LOG_DIR="/var/log/omnisec"

# Colors for output (printf format strings)
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# =============================================================================
# Helper Functions
# =============================================================================

info()    { printf "  ${BLUE}◆${NC} %s\n" "$1"; }
success() { printf "  ${GREEN}✓${NC} %s\n" "$1"; }
warn()    { printf "  ${YELLOW}⚠${NC} %s\n" "$1"; }
fail()    { printf "  ${RED}✗${NC} %s\n" "$1"; }

# Portable redirection: check if a command exists
has_cmd() { command -v "$1" >/dev/null 2>&1; }

# Detect if a port is in use (works on Linux and macOS)
# Uses actual TCP connection attempt as primary method — more reliable than
# process listing (lsof needs sudo to see other users' processes on macOS)
port_in_use() {
    port=$1
    # Method 1: nc -z — actually tries to connect to the port (most reliable)
    # Wrap with timeout to prevent hanging on filtered/dropped ports
    if has_cmd nc; then
        if has_cmd timeout; then
            timeout 3 nc -z 127.0.0.1 "$port" >/dev/null 2>&1 && return 0 || return 1
        else
            nc -z 127.0.0.1 "$port" >/dev/null 2>&1 && return 0 || return 1
        fi
    fi
    # Method 2: ss — fast, Linux only
    if has_cmd ss; then
        ss -tlnp "sport = :$port" 2>/dev/null | grep -q LISTEN && return 0 || return 1
    fi
    # Method 3: lsof with sudo fallback (needed on macOS for other users' processes)
    if has_cmd lsof; then
        lsof -i :"$port" 2>/dev/null | grep -q LISTEN && return 0 || return 1
        # On macOS, lsof without sudo may miss processes owned by other users
        if [ "${OS}" = "Darwin" ]; then
            sudo lsof -i :"$port" 2>/dev/null | grep -q LISTEN && return 0 || return 1
        fi
    fi
    # Method 4: netstat
    if has_cmd netstat; then
        netstat -an 2>/dev/null | grep -q "LISTEN.*:$port " && return 0 || return 1
    fi
    # Method 5: Python socket bind test (most portable fallback)
    if has_cmd python3; then
        python3 -c "import socket; s=socket.socket(); s.bind(('127.0.0.1', $port)); s.close()" 2>/dev/null && return 1 || return 0
    fi
    # Method 6: /dev/tcp (bash-specific, but works on many systems)
    (echo > /dev/tcp/127.0.0.1/"$port") 2>/dev/null && return 0 || return 1
}

# Track in-memory allocated ports to prevent conflicts
ALLOCATED_PORTS=""

already_allocated() {
    port=$1
    for ap in $ALLOCATED_PORTS; do
        [ "$ap" = "$port" ] && return 0
    done
    return 1
}

find_free_port() {
    port=$1
    max_port="${2:-$((port + 100))}"
    while [ "$port" -le "$max_port" ]; do
        if ! port_in_use "$port" && ! already_allocated "$port"; then
            ALLOCATED_PORTS="$ALLOCATED_PORTS $port"
            printf "%s" "$port"
            return 0
        fi
        port=$((port + 1))
    done
    printf ""
    return 1
}

# Platform-specific checksum verification
verify_checksum() {
    file=$1
    checksum_file=$2

    if has_cmd sha256sum; then
        ACTUAL_CHECKSUM=$(sha256sum "$file" | awk '{print $1}')
        STATED_CHECKSUM=$(grep "omnisec-daemon" "$checksum_file" | head -1 | awk '{print $1}')
    elif has_cmd shasum; then
        ACTUAL_CHECKSUM=$(shasum -a 256 "$file" | awk '{print $1}')
        STATED_CHECKSUM=$(grep "omnisec-daemon" "$checksum_file" | head -1 | awk '{print $1}')
    elif has_cmd gsha256sum; then
        ACTUAL_CHECKSUM=$(gsha256sum "$file" | awk '{print $1}')
        STATED_CHECKSUM=$(grep "omnisec-daemon" "$checksum_file" | head -1 | awk '{print $1}')
    else
        warn "No checksum tool found (tried sha256sum, shasum, gsha256sum)"
        return 1
    fi

    if [ -n "$STATED_CHECKSUM" ] && [ "$ACTUAL_CHECKSUM" = "$STATED_CHECKSUM" ]; then
        return 0
    else
        return 1
    fi
}

parse_json_array_len() {
    json=$1
    key="${2:-agents}"
    if has_cmd python3; then
        printf "%s" "$json" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d.get('$key', [])))" 2>/dev/null || printf "0"
    elif has_cmd jq; then
        printf "%s" "$json" | jq ".[\"$key\"] | length" 2>/dev/null || printf "0"
    else
        printf "0"
    fi
}

# Get file size in bytes (portable)
file_size_bytes() {
    fpath=$1
    if has_cmd stat; then
        # Try GNU stat first, then BSD stat
        stat -c%s "$fpath" 2>/dev/null || stat -f%z "$fpath" 2>/dev/null || printf "0"
    elif has_cmd wc; then
        wc -c < "$fpath" 2>/dev/null || printf "0"
    else
        printf "0"
    fi
}

# =============================================================================
# Main Installation Flow
# =============================================================================

printf "\n"
printf "╔═══════════════════════════════════════════════════════════════╗\n"
printf "║         OmniSec Reliability v0.1 — One-Command Install       ║\n"
printf "╚═══════════════════════════════════════════════════════════════╝\n"
printf "\n"

# =============================================================================
# Step 1: Platform Detection
# =============================================================================
printf "━━━ Step 1: Platform Detection ━━━\n"

OS="$(uname -s)"
ARCH="$(uname -m)"

info "OS:   ${OS}"
info "Arch: ${ARCH}"

case "${OS}" in
    Linux|Darwin) ;;
    *)
        fail "Unsupported OS: ${OS}. OmniSec requires Linux or macOS."
        exit 1
        ;;
esac

case "${ARCH}" in
    x86_64)  BINARY_ARCH="amd64" ;;
    aarch64|arm64) BINARY_ARCH="arm64" ;;
    *)
        fail "Unsupported architecture: ${ARCH}"
        exit 1
        ;;
esac

# Determine OS tag for binary download
case "${OS}" in
    Linux)  OS_TAG="linux" ;;
    Darwin) OS_TAG="darwin" ;;
esac

# Binary name: try platform-specific first, fall back to generic
BINARY_NAME_OS_ARCH="omnisec-daemon-${OS_TAG}-${BINARY_ARCH}"
BINARY_NAME_ARCH="omnisec-daemon-${BINARY_ARCH}"

success "Detected ${OS_TAG}/${BINARY_ARCH}"
printf "\n"

# =============================================================================
# Step 2: Prerequisites Check
# =============================================================================
printf "━━━ Step 2: Prerequisites ━━━\n"

# Check curl
if ! has_cmd curl; then
    fail "curl is required. Install it first."
    exit 1
fi
success "curl found"

# Auto-install Docker if not found (Linux only)
if ! has_cmd docker; then
    if [ "${OS}" = "Linux" ]; then
        info "Docker not found — installing via get.docker.com..."
        curl -fsSL https://get.docker.com | sh 2>&1 || {
            fail "Docker installation failed. Install manually:"
            printf "    curl -fsSL https://get.docker.com | sh\n"
            exit 1
        }
        success "Docker installed"
    else
        fail "Docker not found. Install Docker Desktop first:"
        printf "    https://docs.docker.com/desktop/install/mac-install/\n"
        exit 1
    fi
fi

# Now check Docker daemon status
DOCKER_VERSION=$(docker --version 2>/dev/null || printf "Docker CLI")
success "${DOCKER_VERSION}"

_check_docker_running() {
    docker info >/dev/null 2>&1 && return 0
    # Fallback: try sudo docker info (for users not in the docker group on Linux)
    if [ "${OS}" = "Linux" ]; then
        sudo docker info >/dev/null 2>&1 && return 0
    fi
    return 1
}

if ! _check_docker_running; then
    warn "Docker daemon is not running — attempting to start"
    case "${OS}" in
        Linux)
            # Try multiple methods to start Docker daemon
            if has_cmd systemctl; then
                sudo systemctl enable docker 2>/dev/null || true
                sudo systemctl start docker 2>/dev/null || true
            fi
            if ! _check_docker_running; then
                sudo service docker start 2>/dev/null || true
            fi
            # Last resort: start dockerd directly
            if ! _check_docker_running && has_cmd dockerd; then
                info "Starting dockerd directly..."
                sudo dockerd >/dev/null 2>&1 &
                sleep 3
            fi
            ;;
        Darwin)
            open -a Docker 2>/dev/null || true
            warn "If Docker Desktop doesn't start automatically, open it manually"
            ;;
    esac

    info "Waiting for Docker daemon (up to 120s)..."
    attempt=0
    while ! _check_docker_running && [ "$attempt" -lt 12 ]; do
        sleep 10
        attempt=$((attempt + 1))
    done
    if ! _check_docker_running; then
        fail "Docker daemon could not be started after retries"
        warn "Try starting Docker manually:"
        if [ "${OS}" = "Linux" ]; then
            printf "    sudo dockerd > /dev/null 2>&1 &\n"
            printf "    # then re-run this installer\n"
        else
            printf "    Open Docker Desktop application\n"
        fi
        exit 1
    fi
    success "Docker daemon is now running"
else
    success "Docker daemon is running"
fi
printf "\n"

# =============================================================================
# Step 3: Stop Existing Installation
# =============================================================================
printf "━━━ Step 3: Clean Up Existing Installation ━━━\n"

# Stop daemon if running
if has_cmd omnisec-daemon || [ -f "${DAEMON_BIN}" ]; then
    warn "Existing installation found. Cleaning up..."

    # Stop systemd service (Linux)
    if [ "${OS}" = "Linux" ] && systemctl is-active --quiet omnisec-daemon 2>/dev/null; then
        sudo systemctl stop omnisec-daemon 2>/dev/null || true
        sudo systemctl disable omnisec-daemon 2>/dev/null || true
    fi

    # Stop launchd service (macOS)
    if [ "${OS}" = "Darwin" ] && [ -f /Library/LaunchDaemons/com.omnisec.daemon.plist ]; then
        sudo launchctl unload /Library/LaunchDaemons/com.omnisec.daemon.plist 2>/dev/null || true
    fi

    # Kill any running daemon process
    pkill -f omnisec-daemon 2>/dev/null || true

    warn "Removing old binary and configuration..."
    sudo rm -f "${DAEMON_BIN}" 2>/dev/null || true
    sudo rm -f /etc/systemd/system/omnisec-daemon.service 2>/dev/null || true
    sudo rm -f /Library/LaunchDaemons/com.omnisec.daemon.plist 2>/dev/null || true
fi

# Stop and remove Docker container
if docker ps -a --format '{{.Names}}' 2>/dev/null | grep -q "^omnisec$"; then
    warn "Existing Docker container found. Stopping and removing..."
    docker stop omnisec >/dev/null 2>&1 || true
    docker rm omnisec >/dev/null 2>&1 || true
fi

success "Cleanup complete"
printf "\n"

# =============================================================================
# Step 4: Download Daemon Binary
# =============================================================================
printf "━━━ Step 4: Downloading Daemon Binary ━━━\n"

# Try platform-specific binary first, fall back to generic
BINARY_URL="${GITHUB_RELEASES}/${BINARY_NAME_OS_ARCH}"
FALLBACK_URL="${GITHUB_RELEASES}/${BINARY_NAME_ARCH}"

# Create temp directory
TMP_DIR=$(mktemp -d)
trap 'rm -rf "${TMP_DIR}"' EXIT

info "Downloading omnisec-daemon binary..."
if curl -fsSL "${BINARY_URL}" -o "${TMP_DIR}/omnisec-daemon" 2>/dev/null; then
    info "Downloaded: ${BINARY_NAME_OS_ARCH}"
elif curl -fsSL "${FALLBACK_URL}" -o "${TMP_DIR}/omnisec-daemon" 2>/dev/null; then
    info "Downloaded: ${BINARY_NAME_ARCH} (generic fallback)"
else
    fail "Failed to download binary from:"
    printf "    %s\n" "${BINARY_URL}"
    printf "\n"
    warn "Possible issues:"
    printf "    • Release %s may not have binaries for %s/%s\n" "${RELEASE_TAG}" "${OS_TAG}" "${BINARY_ARCH}"
    printf "    • Check releases: https://github.com/%s/%s/releases\n" "${REPO_OWNER}" "${REPO_NAME}"
    exit 1
fi

# Verify file is not empty
if [ ! -s "${TMP_DIR}/omnisec-daemon" ]; then
    fail "Downloaded binary is empty. Release may not have correct assets."
    exit 1
fi

# Check binary size — real daemon should be several MB, not a few KB
BINARY_SIZE=$(file_size_bytes "${TMP_DIR}/omnisec-daemon")
if [ "$BINARY_SIZE" -lt 1000000 ] 2>/dev/null; then
    warn "Binary is only ${BINARY_SIZE} bytes — expected a multi-MB executable"
    warn "This may be a placeholder or broken release asset."
    warn "Release: https://github.com/${REPO_OWNER}/${REPO_NAME}/releases/tag/${RELEASE_TAG}"
fi

chmod +x "${TMP_DIR}/omnisec-daemon"
success "Binary downloaded ($(du -h "${TMP_DIR}/omnisec-daemon" | cut -f1))"
printf "\n"

# =============================================================================
# Step 5: Verify SHA256 Checksum
# =============================================================================
printf "━━━ Step 5: Verifying Binary Checksum ━━━\n"

CHECKSUM_FILE="${BINARY_NAME_OS_ARCH}.sha256"
CHECKSUM_FALLBACK="${BINARY_NAME_ARCH}.sha256"
CHECKSUM_URL="${GITHUB_RELEASES}/${CHECKSUM_FILE}"
CHECKSUM_URL_FALLBACK="${GITHUB_RELEASES}/${CHECKSUM_FALLBACK}"

if curl -fsSL "${CHECKSUM_URL}" -o "${TMP_DIR}/checksum.sha256" 2>/dev/null; then
    :
elif curl -fsSL "${CHECKSUM_URL_FALLBACK}" -o "${TMP_DIR}/checksum.sha256" 2>/dev/null; then
    :
else
    warn "Checksum file not found — skipping verification"
fi

if [ -f "${TMP_DIR}/checksum.sha256" ]; then
    if verify_checksum "${TMP_DIR}/omnisec-daemon" "${TMP_DIR}/checksum.sha256"; then
        success "Checksum verified"
    else
        fail "Checksum mismatch!"
        exit 1
    fi
fi
printf "\n"

# =============================================================================
# Step 6: Install Daemon Binary
# =============================================================================
printf "━━━ Step 6: Installing Daemon Binary ━━━\n"

sudo mkdir -p "${INSTALL_DIR}"
sudo cp "${TMP_DIR}/omnisec-daemon" "${DAEMON_BIN}"
sudo chmod 755 "${DAEMON_BIN}"

success "Installed to ${DAEMON_BIN}"
printf "\n"

# =============================================================================
# Step 7: Configure and Start Daemon
# =============================================================================
printf "━━━ Step 7: Starting OmniSec Daemon ━━━\n"

# Create log directory
sudo mkdir -p "${LOG_DIR}"

case "${OS}" in
    # If the binary is clearly a stub (< 1 MB), skip daemon start but continue
    # to the Docker control plane build. The Docker image builds all binaries
    # from source and runs the daemon inside the container.
    BINARY_SIZE="$(file_size_bytes "${DAEMON_BIN}")"
    if [ "$BINARY_SIZE" -lt 1000000 ] 2>/dev/null; then
        warn "Daemon binary is only ${BINARY_SIZE} bytes (expected multi-MB) — skipping host daemon start"
        warn "The Docker control plane will provide complete functionality"
    else
        case "${OS}" in
            Linux)
                # Create systemd service
                sudo tee /etc/systemd/system/omnisec-daemon.service >/dev/null << 'SERVICE_EOF'
[Unit]
Description=OmniSec Daemon - Host-level Process Monitoring
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
ExecStart=/usr/local/bin/omnisec-daemon
Restart=always
RestartSec=10
Environment=DATABASE_URL=postgres://omnisec:omnisec@localhost:5432/omnisec
Environment=NATS_URL=nats://localhost:4222
Environment=OMNISEC_SAFE_MODE=0
Environment=OMNISEC_RECOMMENDATION_ONLY=0
Environment=RUST_LOG=info

[Install]
WantedBy=multi-user.target
SERVICE_EOF

                sudo systemctl daemon-reload
                sudo systemctl enable omnisec-daemon
                sudo systemctl start omnisec-daemon

                if systemctl is-active --quiet omnisec-daemon; then
                    success "Systemd service created and daemon started"
                else
                    warn "Failed to start daemon — continuing without it"
                    warn "The Docker control plane will provide all functionality"
                fi
                ;;

            Darwin)
                # Create launchd plist for macOS
                sudo tee /Library/LaunchDaemons/com.omnisec.daemon.plist >/dev/null << 'PLIST_EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.omnisec.daemon</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/omnisec-daemon</string>
    </array>
    <key>KeepAlive</key>
    <true/>
    <key>RunAtLoad</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/var/log/omnisec/daemon.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/omnisec/daemon.err</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>DATABASE_URL</key>
        <string>postgres://omnisec:omnisec@localhost:5432/omnisec</string>
        <key>NATS_URL</key>
        <string>nats://localhost:4222</string>
        <key>OMNISEC_SAFE_MODE</key>
        <string>0</string>
        <key>OMNISEC_RECOMMENDATION_ONLY</key>
        <string>0</string>
        <key>RUST_LOG</key>
        <string>info</string>
    </dict>
</dict>
</plist>
PLIST_EOF

                sudo launchctl load /Library/LaunchDaemons/com.omnisec.daemon.plist
                success "Launchd plist created and daemon started"
                ;;
        esac
    fi
printf "\n"

# =============================================================================
# Step 8: Wait for Daemon Health
# =============================================================================
printf "━━━ Step 8: Waiting for Daemon Health ━━━\n"

info "Waiting for daemon health endpoint (up to 30s)..."
DAEMON_READY=false
i=1
while [ $i -le 30 ]; do
    if curl -sf http://127.0.0.1:3003/health >/dev/null 2>&1; then
        DAEMON_READY=true
        success "Daemon health endpoint responding on port 3003"
        break
    fi
    sleep 1
    i=$((i + 1))
done

if [ "$DAEMON_READY" = false ]; then
    warn "Daemon health endpoint not yet responding"
    warn "Check logs: sudo journalctl -u omnisec-daemon -n 30 (Linux)"
    warn "           tail -f /var/log/omnisec/daemon.log (macOS)"
fi
printf "\n"

# =============================================================================
# Step 9: Detect Available Ports
# =============================================================================
printf "━━━ Step 9: Checking Port Availability ━━━\n"

DASHBOARD_PORT=$DEFAULT_DASHBOARD_PORT
API_PORT=$DEFAULT_API_PORT
DAEMON_HEALTH_PORT=$DEFAULT_DAEMON_HEALTH_PORT
POSTGRES_PORT=$DEFAULT_POSTGRES_PORT
NATS_PORT=$DEFAULT_NATS_PORT

if port_in_use $DASHBOARD_PORT; then
    NEW_PORT=$(find_free_port $((DASHBOARD_PORT + 1)))
    if [ -z "$NEW_PORT" ]; then
        fail "Cannot find free port for Dashboard"
        exit 1
    fi
    warn "Port $DASHBOARD_PORT occupied → Dashboard will use port $NEW_PORT"
    DASHBOARD_PORT=$NEW_PORT
else
    success "Dashboard port $DASHBOARD_PORT available"
fi

if port_in_use $API_PORT; then
    NEW_PORT=$(find_free_port $((API_PORT + 1)))
    if [ -z "$NEW_PORT" ]; then
        fail "Cannot find free port for API"
        exit 1
    fi
    warn "Port $API_PORT occupied → API will use port $NEW_PORT"
    API_PORT=$NEW_PORT
else
    success "API port $API_PORT available"
fi

# Check PostgreSQL port (5432) — this is commonly occupied by local DBs
if port_in_use $POSTGRES_PORT; then
    NEW_PORT=$(find_free_port $((POSTGRES_PORT + 1)))
    if [ -z "$NEW_PORT" ]; then
        warn "Port $POSTGRES_PORT occupied and no alternative found — skipping host PostgreSQL exposure"
        POSTGRES_PORT=""
    else
        warn "Port $POSTGRES_PORT occupied (likely a local PostgreSQL) → using port $NEW_PORT"
        POSTGRES_PORT=$NEW_PORT
    fi
else
    success "PostgreSQL port $POSTGRES_PORT available"
fi

# Check NATS port (4222)
if port_in_use $NATS_PORT; then
    NEW_PORT=$(find_free_port $((NATS_PORT + 1)))
    if [ -z "$NEW_PORT" ]; then
        warn "Port $NATS_PORT occupied and no alternative found — skipping host NATS exposure"
        NATS_PORT=""
    else
        warn "Port $NATS_PORT occupied → using port $NEW_PORT"
        NATS_PORT=$NEW_PORT
    fi
else
    success "NATS port $NATS_PORT available"
fi

if port_in_use $DAEMON_HEALTH_PORT; then
    NEW_PORT=$(find_free_port $((DAEMON_HEALTH_PORT + 1)))
    if [ -z "$NEW_PORT" ]; then
        fail "Cannot find free port for Daemon Health"
        exit 1
    fi
    warn "Port $DAEMON_HEALTH_PORT occupied → Daemon Health will use port $NEW_PORT"
    DAEMON_HEALTH_PORT=$NEW_PORT
else
    success "Daemon Health port $DAEMON_HEALTH_PORT available"
fi
printf "\n"

# =============================================================================
# Step 10: Start Docker Control Plane
# =============================================================================
printf "━━━ Step 10: Starting OmniSec Control Plane ━━━\n"

# Try to pull the Docker image first
info "Pulling OmniSec Docker image..."
IMAGE_SOURCE="remote"
if docker pull manishbalayan/omnisec:v0.1.0 2>/dev/null; then
    success "Docker image pulled from Docker Hub"
else
    warn "Docker Hub image not found (manishbalayan/omnisec:v0.1.0)"
    info "Attempting to build from source..."

    # Try local build first (when running from a cloned repo)
    BUILD_DIR=""
    if [ -f "deploy/Dockerfile.all-in-one" ]; then
        BUILD_DIR="$(pwd -P 2>/dev/null || pwd)"
        info "Building from local source at ${BUILD_DIR}"
    else
        # When piped (curl | sh), clone the repo to a temp directory
        info "No local source found — cloning repository..."
        BUILD_DIR="${TMP_DIR}/omnisec-repo"
        if has_cmd git; then
            git clone --depth 1 "https://github.com/${REPO_OWNER}/${REPO_NAME}.git" "${BUILD_DIR}" 2>/dev/null && {
                info "Repository cloned to ${BUILD_DIR}"
            } || {
                warn "Failed to clone repository — skipping Docker control plane"
                BUILD_DIR=""
            }
        else
            warn "git not found — cannot clone repository"
            warn "Install git or clone manually: git clone https://github.com/${REPO_OWNER}/${REPO_NAME}.git"
            BUILD_DIR=""
        fi
    fi

    if [ -n "$BUILD_DIR" ] && [ -f "${BUILD_DIR}/deploy/Dockerfile.all-in-one" ]; then
        info "Building Docker image (this may take 5-10 minutes)..."
        docker build -t manishbalayan/omnisec:v0.1.0 \
            -f "${BUILD_DIR}/deploy/Dockerfile.all-in-one" \
            "${BUILD_DIR}" 2>&1 && {
            success "Docker image built from source"
            IMAGE_SOURCE="local"
        } || {
            warn "Local build failed — skipping Docker control plane"
            warn "The host daemon is still installed at ${DAEMON_BIN}"
            IMAGE_SOURCE="none"
        }
    else
        warn "Cannot build Docker image — skipping Docker control plane"
        warn "The host daemon is still installed at ${DAEMON_BIN}"
        IMAGE_SOURCE="none"
    fi
fi

if [ "$IMAGE_SOURCE" = "none" ]; then
    warn "Continuing with host daemon only (no Docker control plane)"
else
    # Build docker run command as a shell string (POSIX-compatible, no arrays)
    DOCKER_CMD="docker run --name omnisec"
    DOCKER_CMD="${DOCKER_CMD} -p 127.0.0.1:${DASHBOARD_PORT}:3000"
    DOCKER_CMD="${DOCKER_CMD} -p 127.0.0.1:${API_PORT}:3002"

    # Only expose PostgreSQL if port was successfully allocated
    if [ -n "$POSTGRES_PORT" ]; then
        DOCKER_CMD="${DOCKER_CMD} -p 127.0.0.1:${POSTGRES_PORT}:5432"
    fi
    # Only expose NATS if port was successfully allocated
    if [ -n "$NATS_PORT" ]; then
        DOCKER_CMD="${DOCKER_CMD} -p 127.0.0.1:${NATS_PORT}:4222"
    fi

    DOCKER_CMD="${DOCKER_CMD} -v omnisec_data:/var/lib/omnisec"
    DOCKER_CMD="${DOCKER_CMD} --restart unless-stopped"
    DOCKER_CMD="${DOCKER_CMD} --cap-add SYS_PTRACE --cap-add NET_ADMIN --cap-add DAC_READ_SEARCH"
    DOCKER_CMD="${DOCKER_CMD} -e DASHBOARD_PORT=3000"
    DOCKER_CMD="${DOCKER_CMD} -e OMNISEC_DASHBOARD_EXTERNAL_PORT=${DASHBOARD_PORT}"
    DOCKER_CMD="${DOCKER_CMD} -e OMNISEC_API_EXTERNAL_PORT=${API_PORT}"
    DOCKER_CMD="${DOCKER_CMD} -e OMNISEC_DAEMON_HEALTH_EXTERNAL_PORT=${DAEMON_HEALTH_PORT}"

    # On Linux, mount /proc for agent discovery
    if [ "${OS}" = "Linux" ]; then
        DOCKER_CMD="${DOCKER_CMD} -v /proc:/host/proc:ro"
    fi

    DOCKER_CMD="${DOCKER_CMD} -d manishbalayan/omnisec:v0.1.0"

    info "Starting Docker container..."
    if eval "$DOCKER_CMD" 2>&1; then
        success "Control plane container started"

        # Wait for container to be healthy
        info "Waiting for OmniSec to be healthy (up to 120s)..."
        CONTAINER_READY=false
        i=1
        while [ $i -le 60 ]; do
            HEALTH=$(docker inspect --format='{{.State.Health.Status}}' omnisec 2>/dev/null || printf "starting")
            if [ "${HEALTH}" = "healthy" ]; then
                CONTAINER_READY=true
                success "OmniSec container is healthy!"
                break
            fi
            sleep 2
            i=$((i + 1))
        done

        if [ "$CONTAINER_READY" = false ]; then
            warn "Container may still be starting..."
            warn "Check: docker logs omnisec"
        fi
    else
        fail "Failed to start control plane"
        warn "Check: docker logs omnisec"
        warn "The host daemon is still installed at ${DAEMON_BIN}"
    fi
fi
printf "\n"

# =============================================================================
# Step 11: Verify Services
# =============================================================================
printf "━━━ Step 11: Service Verification ━━━\n"

OVERALL_PASS=true

# Get API key from container (only if container is running)
API_KEY=""
if docker ps --format '{{.Names}}' 2>/dev/null | grep -q "^omnisec$"; then
    API_KEY=$(docker exec omnisec cat /var/lib/omnisec/.api_key 2>/dev/null || printf "")
fi

# 11a. Verify API
if [ -n "$API_KEY" ]; then
    info "Verifying API..."
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -H "X-API-Key: ${API_KEY}" "http://127.0.0.1:${API_PORT}/health" 2>/dev/null || printf "000")
    if [ "$HTTP_CODE" = "200" ]; then
        success "API health endpoint → 200"
    else
        fail "API health endpoint → ${HTTP_CODE}"
        OVERALL_PASS=false
    fi
else
    warn "Skipping API verification (container not running or no API key)"
fi

# 11b. Verify Dashboard
info "Verifying Dashboard..."
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:${DASHBOARD_PORT}" 2>/dev/null || printf "000")
if [ "$HTTP_CODE" = "200" ]; then
    success "Dashboard → 200"
else
    fail "Dashboard → ${HTTP_CODE}"
    OVERALL_PASS=false
fi

# 11c. Verify Daemon Discovery
info "Verifying host discovery..."
if docker ps --format '{{.Names}}' 2>/dev/null | grep -q "^omnisec$" && [ -n "$API_KEY" ]; then
    AGENTS_JSON=$(curl -s -H "X-API-Key: ${API_KEY}" "http://127.0.0.1:${API_PORT}/api/agents" 2>/dev/null || printf "{}")
    AGENT_COUNT=$(parse_json_array_len "$AGENTS_JSON" "agents")
    if [ "$AGENT_COUNT" -gt 0 ] 2>/dev/null; then
        success "Discovered ${AGENT_COUNT} agents"
    else
        warn "No agents discovered yet (daemon may still be scanning)"
    fi
else
    warn "Skipping discovery verification (Docker container not running)"
fi

# 11d. Verify Docker services
if docker ps --format '{{.Names}}' 2>/dev/null | grep -q "^omnisec$"; then
    info "Verifying Docker services..."
    for svc in "nats-server" "postgres" "omnisec-api"; do
        if docker exec omnisec pgrep -x "$svc" >/dev/null 2>&1; then
            success "Service running: $svc"
        else
            if docker exec omnisec pgrep -f "$svc" >/dev/null 2>&1; then
                success "Service running: $svc"
            else
                warn "Service not found: $svc"
            fi
        fi
    done
fi

printf "\n"

# =============================================================================
# Step 12: Display Summary
# =============================================================================
printf "╔═══════════════════════════════════════════════════════════════╗\n"
printf "║               OmniSec Installation Complete!                  ║\n"
printf "╚═══════════════════════════════════════════════════════════════╝\n"
printf "\n"

case "${OS}" in
    Linux)
        printf "  Daemon Service:\n"
        printf "    Status:  %s\n" "$(systemctl is-active omnisec-daemon 2>/dev/null || printf 'unknown')"
        printf "    Binary:  %s\n" "${DAEMON_BIN}"
        printf "    Config:  /etc/systemd/system/omnisec-daemon.service\n"
        printf "\n"
        printf "  Daemon Commands:\n"
        printf "    Logs:    sudo journalctl -u omnisec-daemon -f\n"
        printf "    Status:  sudo systemctl status omnisec-daemon\n"
        printf "    Stop:    sudo systemctl stop omnisec-daemon\n"
        printf "    Start:   sudo systemctl start omnisec-daemon\n"
        ;;
    Darwin)
        printf "  Daemon Service:\n"
        printf "    Status:  %s\n" "$(sudo launchctl list | grep com.omnisec.daemon | awk '{print $1}' || printf 'loaded')"
        printf "    Binary:  %s\n" "${DAEMON_BIN}"
        printf "    Config:  /Library/LaunchDaemons/com.omnisec.daemon.plist\n"
        printf "\n"
        printf "  Daemon Commands:\n"
        printf "    Logs:    tail -f /var/log/omnisec/daemon.log\n"
        printf "    Stop:    sudo launchctl unload /Library/LaunchDaemons/com.omnisec.daemon.plist\n"
        printf "    Start:   sudo launchctl load /Library/LaunchDaemons/com.omnisec.daemon.plist\n"
        ;;
esac
printf "\n"
printf "  Control Plane:\n"
printf "    Dashboard:  http://localhost:${DASHBOARD_PORT}\n"
if docker ps --format '{{.Names}}' 2>/dev/null | grep -q "^omnisec$"; then
    printf "    API:        http://localhost:${API_PORT}\n"
    if [ -n "$API_KEY" ]; then
        printf "    API Key:    ${API_KEY}\n"
    fi
fi
printf "\n"
printf "  Documentation:\n"
printf "    https://github.com/${REPO_OWNER}/${REPO_NAME}\n"
printf "\n"
printf "╔═══════════════════════════════════════════════════════════════╗\n"
if [ "$OVERALL_PASS" = true ]; then
printf "║  Status: ✅ INSTALLATION SUCCESSFUL                          ║\n"
else
printf "║  Status: ⚠️ INSTALLED WITH WARNINGS                         ║\n"
fi
printf "╚═══════════════════════════════════════════════════════════════╝\n"
printf "\n"

# Try to open dashboard
case "${OS}" in
    Linux)
        (xdg-open "http://localhost:${DASHBOARD_PORT}" 2>/dev/null || true) &
        ;;
    Darwin)
        (open "http://localhost:${DASHBOARD_PORT}" 2>/dev/null || true) &
        ;;
esac
