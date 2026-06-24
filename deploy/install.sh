#!/usr/bin/env bash
# =============================================================================
# OmniSec One-Command Installer
# =============================================================================
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

INSTALL_DIR="/usr/local/bin"
DAEMON_BIN="${INSTALL_DIR}/omnisec-daemon"
LOG_DIR="/var/log/omnisec"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# =============================================================================
# Helper Functions
# =============================================================================

info()    { echo -e "  ${BLUE}◆${NC} $1"; }
success() { echo -e "  ${GREEN}✓${NC} $1"; }
warn()    { echo -e "  ${YELLOW}⚠${NC} $1"; }
fail()    { echo -e "  ${RED}✗${NC} $1"; }

# Detect if a port is in use (works on Linux and macOS)
port_in_use() {
    local port=$1
    if command -v ss &>/dev/null; then
        ss -tlnp "sport = :$port" 2>/dev/null | grep -q LISTEN && return 0 || return 1
    elif command -v netstat &>/dev/null; then
        netstat -an 2>/dev/null | grep -q "LISTEN.*:$port " && return 0 || return 1
    elif command -v lsof &>/dev/null; then
        lsof -i :"$port" 2>/dev/null | grep -q LISTEN && return 0 || return 1
    else
        (echo > /dev/tcp/127.0.0.1/"$port") 2>/dev/null && return 0 || return 1
    fi
}

# Track in-memory allocated ports to prevent conflicts
ALLOCATED_PORTS=""

already_allocated() {
    local port=$1 ap
    for ap in $ALLOCATED_PORTS; do
        [ "$ap" = "$port" ] && return 0
    done
    return 1
}

find_free_port() {
    local port=$1
    local max_port=${2:-$((port + 100))}
    while [ "$port" -le "$max_port" ]; do
        if ! port_in_use "$port" && ! already_allocated "$port"; then
            ALLOCATED_PORTS="$ALLOCATED_PORTS $port"
            echo "$port"
            return 0
        fi
        port=$((port + 1))
    done
    echo ""
    return 1
}

# Platform-specific checksum verification
verify_checksum() {
    local file=$1
    local checksum_file=$2

    if command -v sha256sum &>/dev/null; then
        ACTUAL_CHECKSUM=$(sha256sum "$file" | awk '{print $1}')
        STATED_CHECKSUM=$(grep -E "omnisec-daemon" "$checksum_file" | head -1 | awk '{print $1}')
    elif command -v shasum &>/dev/null; then
        ACTUAL_CHECKSUM=$(shasum -a 256 "$file" | awk '{print $1}')
        STATED_CHECKSUM=$(grep -E "omnisec-daemon" "$checksum_file" | head -1 | awk '{print $1}')
    elif command -v gsha256sum &>/dev/null; then
        ACTUAL_CHECKSUM=$(gsha256sum "$file" | awk '{print $1}')
        STATED_CHECKSUM=$(grep -E "omnisec-daemon" "$checksum_file" | head -1 | awk '{print $1}')
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
    local json=$1
    local key=${2:-agents}
    if command -v python3 &>/dev/null; then
        echo "$json" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d.get('$key', [])))" 2>/dev/null || echo "0"
    elif command -v jq &>/dev/null; then
        echo "$json" | jq ".[\"$key\"] | length" 2>/dev/null || echo "0"
    else
        echo "-1"
    fi
}

# =============================================================================
# Main Installation Flow
# =============================================================================

echo ""
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║         OmniSec Reliability v0.1 — One-Command Install       ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""

# =============================================================================
# Step 1: Platform Detection
# =============================================================================
echo "━━━ Step 1: Platform Detection ━━━"

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
echo ""

# =============================================================================
# Step 2: Prerequisites Check
# =============================================================================
echo "━━━ Step 2: Prerequisites ━━━"

# Check curl
if ! command -v curl &>/dev/null; then
    fail "curl is required. Install it first."
    exit 1
fi
success "curl found: $(curl --version | head -1 | awk '{print $2}')"

# Check Docker
if command -v docker &>/dev/null; then
    DOCKER_VERSION=$(docker --version 2>/dev/null || echo "Docker CLI")
    success "${DOCKER_VERSION}"

    # Check if Docker daemon is running
    if ! docker info &>/dev/null; then
        warn "Docker daemon is not running — attempting to start"
        case "${OS}" in
            Linux)
                sudo systemctl start docker 2>/dev/null || sudo service docker start 2>/dev/null || true
                ;;
            Darwin)
                open -a Docker 2>/dev/null || true
                warn "If Docker Desktop doesn't start automatically, open it manually"
                ;;
        esac

        info "Waiting for Docker daemon (up to 120s)..."
        attempt=0
        while ! docker info &>/dev/null && [ "$attempt" -lt 12 ]; do
            sleep 10
            attempt=$((attempt + 1))
        done
        if ! docker info &>/dev/null; then
            fail "Docker daemon could not be started after retries"
            exit 1
        fi
        success "Docker daemon is now running"
    else
        success "Docker daemon is running"
    fi
else
    fail "Docker not found. Install Docker first:"
    echo "    Linux:   curl -fsSL https://get.docker.com | sh"
    echo "    macOS:   https://docs.docker.com/desktop/install/mac-install/"
    exit 1
fi
echo ""

# =============================================================================
# Step 3: Stop Existing Installation
# =============================================================================
echo "━━━ Step 3: Clean Up Existing Installation ━━━"

# Stop daemon if running
if command -v omnisec-daemon &>/dev/null || [ -f "${DAEMON_BIN}" ]; then
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
    docker stop omnisec > /dev/null 2>&1 || true
    docker rm omnisec > /dev/null 2>&1 || true
fi

success "Cleanup complete"
echo ""

# =============================================================================
# Step 4: Download Daemon Binary
# =============================================================================
echo "━━━ Step 4: Downloading Daemon Binary ━━━"

# Try platform-specific binary first (e.g. omnisec-daemon-darwin-arm64),
# fall back to generic (e.g. omnisec-daemon-arm64)
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
    echo "    ${BINARY_URL}"
    echo ""
    warn "Possible issues:"
    echo "    • Release ${RELEASE_TAG} may not have binaries for ${OS_TAG}/${BINARY_ARCH}"
    echo "    • Check releases: https://github.com/${REPO_OWNER}/${REPO_NAME}/releases"
    exit 1
fi

# Verify file is not empty
if [ ! -s "${TMP_DIR}/omnisec-daemon" ]; then
    fail "Downloaded binary is empty. Release may not have correct assets."
    exit 1
fi

chmod +x "${TMP_DIR}/omnisec-daemon"
success "Binary downloaded ($(du -h "${TMP_DIR}/omnisec-daemon" | cut -f1))"
echo ""

# =============================================================================
# Step 5: Verify SHA256 Checksum
# =============================================================================
echo "━━━ Step 5: Verifying Binary Checksum ━━━"

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
echo ""

# =============================================================================
# Step 6: Install Daemon Binary
# =============================================================================
echo "━━━ Step 6: Installing Daemon Binary ━━━"

sudo mkdir -p "${INSTALL_DIR}"
sudo cp "${TMP_DIR}/omnisec-daemon" "${DAEMON_BIN}"
sudo chmod 755 "${DAEMON_BIN}"

success "Installed to ${DAEMON_BIN}"
echo ""

# =============================================================================
# Step 7: Configure and Start Daemon
# =============================================================================
echo "━━━ Step 7: Starting OmniSec Daemon ━━━"

# Create log directory
sudo mkdir -p "${LOG_DIR}"

case "${OS}" in
    Linux)
        # Create systemd service
        sudo tee /etc/systemd/system/omnisec-daemon.service > /dev/null << 'SERVICE_EOF'
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
            fail "Failed to start daemon. Check: sudo journalctl -u omnisec-daemon -n 50"
            exit 1
        fi
        ;;

    Darwin)
        # Create launchd plist for macOS
        sudo tee /Library/LaunchDaemons/com.omnisec.daemon.plist > /dev/null << 'PLIST_EOF'
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
echo ""

# =============================================================================
# Step 8: Wait for Daemon Health
# =============================================================================
echo "━━━ Step 8: Waiting for Daemon Health ━━━"

info "Waiting for daemon health endpoint (up to 30s)..."
DAEMON_READY=false
for i in $(seq 1 30); do
    if curl -sf http://127.0.0.1:3003/health > /dev/null 2>&1; then
        DAEMON_READY=true
        success "Daemon health endpoint responding on port 3003"
        break
    fi
    sleep 1
done

if [ "$DAEMON_READY" = false ]; then
    warn "Daemon health endpoint not yet responding"
    warn "Check logs: sudo journalctl -u omnisec-daemon -n 30 (Linux)"
    warn "           tail -f /var/log/omnisec/daemon.log (macOS)"
fi
echo ""

# =============================================================================
# Step 9: Detect Available Ports
# =============================================================================
echo "━━━ Step 9: Checking Port Availability ━━━"

DASHBOARD_PORT=$DEFAULT_DASHBOARD_PORT
API_PORT=$DEFAULT_API_PORT
DAEMON_HEALTH_PORT=$DEFAULT_DAEMON_HEALTH_PORT

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
echo ""

# =============================================================================
# Step 10: Start Docker Control Plane
# =============================================================================
echo "━━━ Step 10: Starting OmniSec Control Plane ━━━"

# Pull the Docker image first
info "Pulling OmniSec Docker image..."
if docker pull manishbalayan/omnisec:v0.1.0; then
    success "Docker image pulled"
else
    warn "Docker image pull failed - attempting to use local build if available"
fi

DOCKER_RUN_ARGS=(
    --name omnisec
    -p "127.0.0.1:${DASHBOARD_PORT}:3000"
    -p "127.0.0.1:${API_PORT}:3002"
    -p "127.0.0.1:5432:5432"
    -p "127.0.0.1:4222:4222"
    -v omnisec_data:/var/lib/omnisec
    --restart unless-stopped
    --cap-add SYS_PTRACE
    --cap-add NET_ADMIN
    --cap-add DAC_READ_SEARCH
    -e "DASHBOARD_PORT=3000"
    -e "OMNISEC_DASHBOARD_EXTERNAL_PORT=${DASHBOARD_PORT}"
    -e "OMNISEC_API_EXTERNAL_PORT=${API_PORT}"
    -e "OMNISEC_DAEMON_HEALTH_EXTERNAL_PORT=${DAEMON_HEALTH_PORT}"
    -d
)

# On Linux, mount /proc for agent discovery
if [ "${OS}" = "Linux" ]; then
    DOCKER_RUN_ARGS+=(-v /proc:/host/proc:ro)
fi

info "Starting Docker container..."
docker run "${DOCKER_RUN_ARGS[@]}" manishbalayan/omnisec:v0.1.0 2>&1 || {
    fail "Failed to start control plane"
    warn "Check: docker logs omnisec"
    exit 1
}
success "Control plane container started"

# Wait for container to be healthy
info "Waiting for OmniSec to be healthy (up to 120s)..."
CONTAINER_READY=false
for i in $(seq 1 60); do
    HEALTH=$(docker inspect --format='{{.State.Health.Status}}' omnisec 2>/dev/null || echo "starting")
    if [ "${HEALTH}" = "healthy" ]; then
        CONTAINER_READY=true
        success "OmniSec container is healthy!"
        break
    fi
    sleep 2
done

if [ "$CONTAINER_READY" = false ]; then
    warn "Container may still be starting..."
    warn "Check: docker logs omnisec"
fi
echo ""

# =============================================================================
# Step 11: Verify Services
# =============================================================================
echo "━━━ Step 11: Service Verification ━━━"

OVERALL_PASS=true

# Get API key from container
API_KEY=$(docker exec omnisec cat /var/lib/omnisec/.api_key 2>/dev/null || echo "")

# 11a. Verify API
info "Verifying API..."
if [ -n "$API_KEY" ]; then
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -H "X-API-Key: ${API_KEY}" "http://127.0.0.1:${API_PORT}/health" 2>/dev/null || echo "000")
    if [ "$HTTP_CODE" = "200" ]; then
        success "API health endpoint → 200"
    else
        fail "API health endpoint → ${HTTP_CODE}"
        OVERALL_PASS=false
    fi
else
    warn "Could not retrieve API key — skipping API verification"
fi

# 11b. Verify Dashboard
info "Verifying Dashboard..."
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:${DASHBOARD_PORT}" 2>/dev/null || echo "000")
if [ "$HTTP_CODE" = "200" ]; then
    success "Dashboard → 200"
else
    fail "Dashboard → ${HTTP_CODE}"
    OVERALL_PASS=false
fi

# 11c. Verify Daemon Discovery
info "Verifying host discovery..."
if [ -n "$API_KEY" ]; then
    AGENTS_JSON=$(curl -s -H "X-API-Key: ${API_KEY}" "http://127.0.0.1:${API_PORT}/api/agents" 2>/dev/null || echo "{}")
    AGENT_COUNT=$(parse_json_array_len "$AGENTS_JSON" "agents")
    if [ "$AGENT_COUNT" -gt 0 ] 2>/dev/null; then
        success "Discovered ${AGENT_COUNT} agents"
    else
        warn "No agents discovered yet (daemon may still be scanning)"
    fi
else
    warn "Skipping discovery verification (no API key)"
fi

# 11d. Verify Docker services
info "Verifying Docker services..."
for svc in "nats-server" "postgres" "omnisec-api"; do
    if docker exec omnisec pgrep -x "$svc" > /dev/null 2>&1; then
        success "Service running: $svc"
    else
        # Try partial match
        if docker exec omnisec pgrep -f "$svc" > /dev/null 2>&1; then
            success "Service running: $svc"
        else
            warn "Service not found: $svc"
        fi
    fi
done

echo ""

# =============================================================================
# Step 12: Display Summary
# =============================================================================
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║               OmniSec Installation Complete!                  ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""

case "${OS}" in
    Linux)
        echo "  Daemon Service:"
        echo "    Status:  $(systemctl is-active omnisec-daemon 2>/dev/null || echo 'unknown')"
        echo "    Binary:  ${DAEMON_BIN}"
        echo "    Config:  /etc/systemd/system/omnisec-daemon.service"
        echo ""
        echo "  Daemon Commands:"
        echo "    Logs:    sudo journalctl -u omnisec-daemon -f"
        echo "    Status:  sudo systemctl status omnisec-daemon"
        echo "    Stop:    sudo systemctl stop omnisec-daemon"
        echo "    Start:   sudo systemctl start omnisec-daemon"
        ;;
    Darwin)
        echo "  Daemon Service:"
        echo "    Status:  $(sudo launchctl list | grep com.omnisec.daemon | awk '{print $1}' || echo 'loaded')"
        echo "    Binary:  ${DAEMON_BIN}"
        echo "    Config:  /Library/LaunchDaemons/com.omnisec.daemon.plist"
        echo ""
        echo "  Daemon Commands:"
        echo "    Logs:    tail -f /var/log/omnisec/daemon.log"
        echo "    Stop:    sudo launchctl unload /Library/LaunchDaemons/com.omnisec.daemon.plist"
        echo "    Start:   sudo launchctl load /Library/LaunchDaemons/com.omnisec.daemon.plist"
        ;;
esac
echo ""
echo "  Control Plane:"
echo "    Dashboard:  http://localhost:${DASHBOARD_PORT}"
echo "    API:        http://localhost:${API_PORT}"
echo "    API Key:    ${API_KEY:-see container logs: docker exec omnisec cat /var/lib/omnisec/.api_key}"
echo ""
echo "  Docker Commands:"
echo "    Logs:       docker logs -f omnisec"
echo "    Stop:       docker stop omnisec"
echo "    Start:      docker start omnisec"
echo ""
echo "  Documentation:"
echo "    https://github.com/${REPO_OWNER}/${REPO_NAME}"
echo ""
echo "╔═══════════════════════════════════════════════════════════════╗"
if [ "$OVERALL_PASS" = true ]; then
echo "║  Status: ✅ INSTALLATION SUCCESSFUL                          ║"
else
echo "║  Status: ⚠️ INSTALLED WITH WARNINGS                         ║"
fi
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""

# Try to open dashboard
case "${OS}" in
    Linux)
        (xdg-open "http://localhost:${DASHBOARD_PORT}" 2>/dev/null || true) &
        ;;
    Darwin)
        (open "http://localhost:${DASHBOARD_PORT}" 2>/dev/null || true) &
        ;;
esac
