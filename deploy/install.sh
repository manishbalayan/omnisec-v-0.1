#!/usr/bin/env bash
# =============================================================================
# OmniSec Installer
# =============================================================================
# One-command installation: pulls pre-built binaries and sets up services.
#
# What it does:
#   1. Detects OS, architecture, and builds
#   2. Downloads omnisec-daemon binary from GitHub Releases
#   3. Verifies checksum
#   4. Installs daemon binary to /usr/local/bin/
#   5. Creates systemd service
#   6. Starts Docker control plane stack
#   7. Prints dashboard URL
#
# Prerequisites: curl, Docker
# No Rust/Cargo/compilation on target machine.
# =============================================================================

set -e

# =============================================================================
# Configuration
# =============================================================================
REPO_OWNER="${GITHUB_REPO_OWNER:-manishbalayan}"
REPO_NAME="${GITHUB_REPO_NAME:-omnisec-v-0.1}"
RELEASE_TAG="${OMNISEC_VERSION:-v0.1.0-daemon}"
DAEMON_BIN_DIR="${OMNISEC_DAEMON_BIN_DIR:-https://github.com/${REPO_OWNER}/${REPO_NAME}/releases/download/${RELEASE_TAG}}"

# Default ports
DEFAULT_DASHBOARD_PORT=3000
DEFAULT_API_PORT=3002
DEFAULT_DAEMON_HEALTH_PORT=3003

# Track in-memory allocated ports to prevent conflicts
ALLOCATED_PORTS=""

# Detect if a port is in use (works on Linux and macOS)
port_in_use() {
    local port=$1
    if command -v ss &>/dev/null; then
        ss -tlnp "sport = :$port" 2>/dev/null | grep -q LISTEN && return 0 || return 1
    elif command -v netstat &>/dev/null; then
        netstat -an 2>/dev/null | grep -q "LISTEN.*:$port " && return 0 || return 1
    elif command -v lsof &>/dev/null; then
        lsof -i :$port 2>/dev/null | grep -q LISTEN && return 0 || return 1
    else
        # Fallback: use /dev/tcp if available (Linux)
        (echo > /dev/tcp/127.0.0.1/$port) 2>/dev/null && return 0 || return 1
    fi
}

# Find the first available port starting from the given port.
already_allocated() {
    local port=$1
    local ap
    for ap in $ALLOCATED_PORTS; do
        [ "$ap" = "$port" ] && return 0
    done
    return 1
}

find_free_port() {
    local port=$1
    local max_port=$2
    max_port="${max_port:-$((port + 100))}"
    while [ $port -le $max_port ]; do
        if ! port_in_use $port && ! already_allocated $port; then
            ALLOCATED_PORTS="$ALLOCATED_PORTS $port"
            echo $port
            return 0
        fi
        port=$((port + 1))
    done
    echo ""
    return 1
}

# =============================================================================
# Platform Detection
# =============================================================================
OS="$(uname -s)"
ARCH="$(uname -m)"

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  OmniSec Reliability v0.1 - Host-Level Installation"
echo "═══════════════════════════════════════════════════════════════"
echo ""

echo "◆ Platform Detection"
echo "  OS:   ${OS}"
echo "  Arch: ${ARCH}"
echo ""

case "${OS}" in
    Linux)
        ;;
    Darwin)
        ;;
    *)
        echo "✗ Unsupported OS: ${OS}"
        echo "  OmniSec requires Linux or macOS."
        echo "  For other platforms, use Docker: https://docs.docker.com/get-docker/"
        exit 1
        ;;
esac

# Determine architecture for binary download
case "${ARCH}" in
    x86_64)
        BINARY_ARCH="amd64"
        ;;
    aarch64|arm64)
        BINARY_ARCH="arm64"
        ;;
    *)
        echo "✗ Unsupported architecture: ${ARCH}"
        exit 1
        ;;
esac

echo "◆ Architecture Selection"
echo "  Host architecture: ${ARCH}"
echo "  Binary architecture: ${BINARY_ARCH}"
echo ""

# =============================================================================
# Step 1: Check for Docker
# =============================================================================
echo "◆ Checking for Docker"

if command -v docker &>/dev/null; then
    DOCKER_VERSION=$(docker --version 2>/dev/null)
    echo "  ✓ ${DOCKER_VERSION}"
else
    echo "  ✗ Docker not found"
    echo ""
    echo "  OmniSec requires Docker to run the control plane."
    echo ""
    echo "  Install Docker:"
    echo "    Linux:   curl -fsSL https://get.docker.com | sh"
    echo "    macOS:   https://docs.docker.com/desktop/install/mac-install/"
    echo ""
    echo "  Proceeding with installer; Docker will be started automatically if possible."
    echo ""
fi

# Check if Docker CLI exists
if command -v docker >/dev/null 2>&1; then
    # If Docker daemon is not reachable, try to start it automatically
    if ! docker info >/dev/null 2>&1; then
        echo "  ✗ Docker daemon is not running – attempting automatic start"
        # Attempt to start Docker based on OS
        if [ "${OS}" = "Linux" ]; then
            sudo systemctl start docker || sudo service docker start || true
        elif [ "${OS}" = "Darwin" ]; then
            open -a Docker 2>/dev/null || true
        fi
        # Retry docker info for up to 120 seconds
        ATTEMPTS=0
        while ! docker info >/dev/null 2>&1 && [ $ATTEMPTS -lt 12 ]; do
            sleep 10
            ATTEMPTS=$((ATTEMPTS+1))
        done
        if ! docker info >/dev/null 2>&1; then
            echo "  ✗ Docker daemon could not be started after retries"
            exit 1
        fi
    fi
else
    echo "  ✗ Docker CLI not found – cannot proceed"
    exit 1
fi

echo "  ✓ Docker is running"
echo ""

# =============================================================================
# Step 2: Stop existing installation
# =============================================================================
echo "◆ Checking for existing installation"

if docker ps -a --format '{{.Names}}' | grep -q "^omnisec$"; then
    echo "  Existing container found. Stopping and removing..."
    docker stop omnisec > /dev/null 2>&1 || true
    docker rm omnisec > /dev/null 2>&1 || true
    echo "  ✓ Removed existing container"
fi

echo ""

# =============================================================================
# Step 3: Download omnisec-daemon binary
# =============================================================================
echo "◆ Downloading omnisec-daemon binary"

BINARY_NAME="omnisec-daemon-${BINARY_ARCH}"
BINARY_URL="${DAEMON_BIN_DIR}/${BINARY_NAME}"

if curl -fsSL "${BINARY_URL}" -o /tmp/omnisec-daemon 2>/dev/null; then
    if [ -f /tmp/omnisec-daemon ]; then
        echo "  Downloaded: ${BINARY_NAME}"
    else
        echo "  ✗ Download failed: Binary not found at ${BINARY_URL}"
        exit 1
    fi
else
    echo "  ✗ Failed to download values from ${BINARY_URL}"
    echo ""
    echo "  Check:"
    echo "    - Network connectivity"
    echo "    - Release ${RELEASE_TAG} exists at ${DAEMON_BIN_DIR}"
    echo ""
    exit 1
fi

# ============================================================================
# Step 4: Download and verify SHA256 checksum
# ============================================================================
echo ""
echo "◆ Verifying binary checksum"

CHECKSUM_FILE="${BINARY_NAME}.sha256"
CHECKSUM_URL="${DAEMON_BIN_DIR}/${CHECKSUM_FILE}"

if curl -fsSL "${CHECKSUM_URL}" -o /tmp/${CHECKSUM_FILE} 2>/dev/null; then
    echo "  Downloaded: ${CHECKSUM_FILE}"
else
    echo "  ✗ Failed to download checksum file"
    exit 1
fi

# Extract the checksum and verify
ACTUAL_CHECKSUM=$(sha256sum /tmp/omnisec-daemon | awk '{print $1}')
STATED_CHECKSUM=$(grep ${BINARY_NAME} /tmp/${CHECKSUM_FILE} | awk '{print $1}')

if [ "$ACTUAL_CHECKSUM" = "$STATED_CHECKSUM" ]; then
    echo "  ✓ Checksum verified: $ACTUAL_CHECKSUM"
else
    echo "  ✗ Checksum mismatch!"
    echo "    Expected: $STATED_CHECKSUM"
    echo "    Actual:   $ACTUAL_CHECKSUM"
    exit 1
fi

echo ""

# =============================================================================
# Step 5: Install daemon binary
# =============================================================================
echo "◆ Installing omnisec-daemon"

chmod +x /tmp/omnisec-daemon
# Install to user-local bin to avoid sudo
INSTALL_DIR="$HOME/.local/bin"
mkdir -p "$INSTALL_DIR"
if cp /tmp/omnisec-daemon "$INSTALL_DIR/omnisec-daemon"; then
    echo "  Installed to $INSTALL_DIR/omnisec-daemon"
else
    echo "  ✗ Failed to install daemon binary"
    exit 1
fi

echo ""

# =============================================================================
# Step 6: Install and start omnisec-daemon
# =============================================================================
echo "◆ Installing and starting omnisec-daemon"

chmod +x "$INSTALL_DIR/omnisec-daemon"

if [ "${OS}" = "Linux" ]; then
    # Linux – use systemd
    cat > /etc/systemd/system/omnisec-daemon.service << EOF
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
EOF
    systemctl daemon-reload
    systemctl enable omnisec-daemon
    systemctl start omnisec-daemon
    echo "  ✓ Systemd service created and daemon started"
else
    # macOS – run daemon in background
    /usr/local/bin/omnisec-daemon &
    DAEMON_PID=$!
    echo "  ✓ OmniSec daemon started in background (PID $DAEMON_PID)"
fi

# Wait for daemon to be ready
echo ""
echo "◆ Waiting for daemon to be ready..."
TIMEOUT=30
ELAPSED=0
while [ $ELAPSED -lt $TIMEOUT ]; do
    if [ "${OS}" = "Linux" ]; then
        systemctl is-active --quiet omnisec-daemon && nc -z localhost 3003 2>/dev/null && echo "  ✓ OmniSec Daemon is ready!" && break
    else
        ps -p $DAEMON_PID >/dev/null && nc -z localhost 3003 2>/dev/null && echo "  ✓ OmniSec Daemon is ready!" && break
    fi
    sleep 1
    ELAPSED=$((ELAPSED + 1))
    echo -n "."
done

echo ""echo ""

if [ ${ELAPSED} -ge ${TIMEOUT} ]; then
    echo "  ⚠ Daemon may still be starting..."
    echo ""
    echo "  Check logs: systemctl status omnisec-daemon"
fi

echo ""

# =============================================================================
# Step 8: Pull Docker image
# ============================================================================
echo "◆ Pulling OmniSec Docker image"

if docker pull manishbalayan/omnisec:v0.1.0 2>&1; then
    echo "  ✓ Docker image pulled"
else
    echo "  ✗ Failed to pull Docker image"
    echo ""
    echo "  Try:"
    echo "    docker pull manishbalayan/omnisec:v0.1.0"
    echo ""
    exit 1
fi

echo ""

# =============================================================================
# Step 9: Detect available ports
# ============================================================================
echo "◆ Checking port availability"

DASHBOARD_PORT=$DEFAULT_DASHBOARD_PORT
API_PORT=$DEFAULT_API_PORT
DAEMON_HEALTH_PORT=$DEFAULT_DAEMON_HEALTH_PORT

if port_in_use $DASHBOARD_PORT; then
    NEW_PORT=$(find_free_port $((DASHBOARD_PORT + 1)))
    if [ -z "$NEW_PORT" ]; then
        echo "  ✗ Cannot find free port for Dashboard"
        exit 1
    fi
    echo "  ⚠ Port $DASHBOARD_PORT occupied → Dashboard will use port $NEW_PORT"
    DASHBOARD_PORT=$NEW_PORT
else
    echo "  ✓ Dashboard port $DASHBOARD_PORT available"
fi

if port_in_use $API_PORT; then
    NEW_PORT=$(find_free_port $((API_PORT + 1)))
    if [ -z "$NEW_PORT" ]; then
        echo "  ✗ Cannot find free port for API"
        exit 1
    fi
    echo "  ⚠ Port $API_PORT occupied → API will use port $NEW_PORT"
    API_PORT=$NEW_PORT
else
    echo "  ✓ API port $API_PORT available"
fi

if port_in_use $DAEMON_HEALTH_PORT; then
    NEW_PORT=$(find_free_port $((DAEMON_HEALTH_PORT + 1)))
    if [ -z "$NEW_PORT" ]; then
        echo "  ✗ Cannot find free port for Daemon Health"
        exit 1
    fi
    echo "  ⚠ Port $DAEMON_HEALTH_PORT occupied → Daemon Health will use port $NEW_PORT"
    DAEMON_HEALTH_PORT=$NEW_PORT
else
    echo "  ✓ Daemon Health port $DAEMON_HEALTH_PORT available"
fi

echo ""

# =============================================================================
# Step 10: Start Docker control plane
# =============================================================================
echo "◆ Starting OmniSec Control Plane"

DOCKER_RUN_ARGS=(
    --name omnisec
    -p "127.0.0.1:${DASHBOARD_PORT}:3000"
    -p "127.0.0.1:${API_PORT}:3002"
    -p "127.0.0.1:${DAEMON_HEALTH_PORT}:3003"
    -v omnisec_data:/var/lib/omnisec
    -p 5432:5432
    -p 4222:4222
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

# Start the container
if docker run "${DOCKER_RUN_ARGS[@]}" manishbalayan/omnisec:v0.1.0 2>&1; then
    echo "  ✓ Control plane is starting"
else
    echo "  ✗ Failed to start control plane"
    echo ""
    echo "  Check Docker logs: docker logs omnisec"
    exit 1
fi

# Wait for Docker stack to be healthy
echo ""
echo "◆ Waiting for OmniSec to be fully healthy..."
TIMEOUT=120
ELAPSED=0
while [ ${ELAPSED} -lt ${TIMEOUT} ]; do
    HEALTH=$(docker inspect --format='{{.State.Health.Status}}' omnisec 2>/dev/null || echo "starting")
    if [ "${HEALTH}" = "healthy" ]; then
        echo "  ✓ OmniSec is ready!"
        break
    fi
    sleep 2
    ELAPSED=$((ELAPSED + 2))
    echo -n "."
done
echo ""

if [ ${ELAPSED} -ge ${TIMEOUT} ]; then
    echo "  ⚠ Still starting..."
    echo ""
    echo "  Check logs: docker logs omnisec"
fi

echo ""

# =============================================================================
# Step 11: Get API key
# =============================================================================
API_KEY=$(docker exec omnisec cat /var/lib/omnisec/.api_key 2>/dev/null || echo "See container logs")

# =============================================================================
# Step 12: Display summary
# =============================================================================
echo "═══════════════════════════════════════════════════════════════"
echo "  OmniSec is running!"
echo ""
echo "  Daemon Service:"
echo "    Status: $(systemctl is-active omnisec-daemon)"
echo "    Binary: /usr/local/bin/omnisec-daemon"
echo "    Config: /etc/systemd/system/omnisec-daemon.service"
echo ""
echo "  Control Plane:"
echo "    Container: omnisec"
echo "    Dashboard: http://localhost:${DASHBOARD_PORT}"
echo "    API:        http://localhost:${API_PORT}"
echo "    API Key:    ${API_KEY}"
echo ""
echo "  Services:"
echo "    PostgreSQL: localhost:5432 (omnisec database)"
echo "    NATS:       localhost:4222 (JetStream enabled)"
echo ""
echo "  Commands:"
echo "    View daemon logs:      journalctl -u omnisec-daemon -f"
echo "    View control plane:    docker logs -f omnisec"
echo "    Stop daemon:           systemctl stop omnisec-daemon"
echo "    Start daemon:          systemctl start omnisec-daemon"
echo "    Stop control plane:    docker stop omnisec"
echo "    Start control plane:   docker start omnisec"
echo "    Remove all:            sudo bash -c 'systemctl stop omnisec-daemon && docker stop omnisec && docker rm omnisec'"
echo ""
echo "  Visit https://github.com/${REPO_OWNER}/${REPO_NAME} for documentation"
echo "═══════════════════════════════════════════════════════════════"
echo ""

# Try to open the dashboard in the browser
case "${OS}" in
    Linux)
        if command -v xdg-open &>/dev/null; then
            xdg-open "http://localhost:${DASHBOARD_PORT}" 2>/dev/null || true
        elif command -v goat &>/dev/null; then
            goat "http://localhost:${DASHBOARD_PORT}" 2>/dev/null || true
        fi
        ;;
    Darwin)
        open "http://localhost:${DASHBOARD_PORT}" 2>/dev/null || true
        ;;
esac
