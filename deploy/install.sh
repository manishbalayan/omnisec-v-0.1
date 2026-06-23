#!/usr/bin/env bash
# =============================================================================
# OmniSec Installer
# =============================================================================
# One-command installation: curl -fsSL https://install.omnisec.ai | sh
#
# What it does:
#   1. Detects the platform (Linux/macOS)
#   2. Checks for Docker (prompts to install if missing)
#   3. Pulls the omnisec/omnisec all-in-one image
#   4. Creates a permanent data volume
#   5. Starts the container
#   6. Opens the dashboard in the browser
#   7. Prints the dashboard URL and API key
# =============================================================================

set -e

# =============================================================================
# Port detection and allocation
# =============================================================================
# OmniSec requires 3 ports: Dashboard (default 3000), API (default 3002),
# Daemon Health (default 3003). If any are occupied, we auto-allocate free ports.
#
# IMPORTANT: Ports are allocated SEQUENTIALLY and tracked in ALLOCATED_PORTS
# to prevent two services from claiming the same port (since Docker hasn't
# started yet, port_in_use alone can't detect in-memory allocations).
# =============================================================================

# Default ports
DEFAULT_DASHBOARD_PORT=3000
DEFAULT_API_PORT=3002
DEFAULT_DAEMON_HEALTH_PORT=3003

# Track in-memory allocated ports to prevent conflicts between sequential checks
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
# Checks both actual OS port usage AND previously allocated ports (from
# earlier find_free_port calls tracked in ALLOCATED_PORTS).
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

OMNISEC_IMAGE="${OMNISEC_IMAGE:-omnisec/omnisec}"
OMNISEC_TAG="${OMNISEC_TAG:-latest}"
OMNISEC_CONTAINER_NAME="${OMNISEC_CONTAINER_NAME:-omnisec}"
OMNISEC_VOLUME_NAME="${OMNISEC_VOLUME_NAME:-omnisec_data}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo ""
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}  OmniSec Reliability v0.1${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo ""

# =============================================================================
# Step 1: Detect platform
# =============================================================================
OS="$(uname -s)"
ARCH="$(uname -m)"

echo -e "${YELLOW}◆ Detecting platform...${NC}"
echo "  OS:   ${OS}"
echo "  Arch: ${ARCH}"

case "${OS}" in
    Linux)  ;;
    Darwin) ;;
    *)
        echo -e "${RED}✗ Unsupported OS: ${OS}${NC}"
        echo "  OmniSec requires Linux or macOS."
        echo "  For other platforms, use Docker: https://docs.docker.com/get-docker/"
        exit 1
        ;;
esac

# =============================================================================
# Step 2: Check for Docker
# =============================================================================
echo ""
echo -e "${YELLOW}◆ Checking for Docker...${NC}"

if command -v docker &>/dev/null; then
    DOCKER_VERSION=$(docker --version 2>/dev/null)
    echo -e "${GREEN}  ✓ ${DOCKER_VERSION}${NC}"
else
    echo -e "${RED}  ✗ Docker not found${NC}"
    echo ""
    echo "  OmniSec requires Docker to run."
    echo ""
    echo "  Install Docker:"
    echo "    Linux:   curl -fsSL https://get.docker.com | sh"
    echo "    macOS:   https://docs.docker.com/desktop/install/mac-install/"
    echo ""
    echo "  After installing Docker, run this installer again:"
    echo "    curl -fsSL https://install.omnisec.ai | sh"
    echo ""
    exit 1
fi

# Check if Docker daemon is running
if ! docker info &>/dev/null; then
    echo -e "${RED}  ✗ Docker daemon is not running${NC}"
    echo ""
    echo "  Start Docker and try again:"
    echo "    Linux:   sudo systemctl start docker"
    echo "    macOS:   Open Docker Desktop application"
    echo ""
    exit 1
fi

# =============================================================================
# Step 3: Stop existing container
# =============================================================================
echo ""
echo -e "${YELLOW}◆ Checking for existing installation...${NC}"

if docker ps -a --format '{{.Names}}' | grep -q "^${OMNISEC_CONTAINER_NAME}$"; then
    echo -e "${YELLOW}  Existing container found. Stopping and removing...${NC}"
    docker stop "${OMNISEC_CONTAINER_NAME}" > /dev/null 2>&1 || true
    docker rm "${OMNISEC_CONTAINER_NAME}" > /dev/null 2>&1 || true
    echo -e "${GREEN}  ✓ Removed existing container${NC}"
fi

# =============================================================================
# Step 4: Pull the image (or build from source if not available)
# =============================================================================
echo ""
echo -e "${YELLOW}◆ Checking for OmniSec image...${NC}"
echo "  Image: ${OMNISEC_IMAGE}:${OMNISEC_TAG}"

# Try to pull the image first
if docker pull "${OMNISEC_IMAGE}:${OMNISEC_TAG}" 2>/dev/null; then
    echo -e "${GREEN}  ✓ Image pulled${NC}"
    IMAGE_TO_USE="${OMNISEC_IMAGE}:${OMNISEC_TAG}"
else
    echo -e "${YELLOW}  ⚠ Image not found on Docker Hub, building from source...${NC}"
    # Create a temporary directory for building
    TMP_BUILD_DIR=$(mktemp -d)
    if git clone https://github.com/manishbalayan/omnisec-v-0.1.git "$TMP_BUILD_DIR" 2>/dev/null; then
        echo "  Cloned repository, building image..."
        if cd "$TMP_BUILD_DIR" && docker build -f deploy/Dockerfile.all-in-one -t omnisec/omnisec .; then
            echo -e "${GREEN}  ✓ Image built successfully${NC}"
            IMAGE_TO_USE="omnisec/omnisec"
            cd -
        else
            echo -e "${RED}  ✗ Failed to build image${NC}"
            rm -rf "$TMP_BUILD_DIR"
            exit 1
        fi
        rm -rf "$TMP_BUILD_DIR"
    else
        echo -e "${RED}  ✗ Failed to clone repository for building${NC}"
        exit 1
    fi
fi

# =============================================================================
# Step 5: Create data volume
# =============================================================================
echo ""
echo -e "${YELLOW}◆ Setting up data persistence...${NC}"

if ! docker volume inspect "${OMNISEC_VOLUME_NAME}" &>/dev/null; then
    docker volume create "${OMNISEC_VOLUME_NAME}" > /dev/null
    echo -e "${GREEN}  ✓ Created volume: ${OMNISEC_VOLUME_NAME}${NC}"
else
    echo -e "${GREEN}  ✓ Using existing volume: ${OMNISEC_VOLUME_NAME}${NC}"
fi

# =============================================================================
# Step 6: Detect available ports
# =============================================================================
echo ""
echo -e "${YELLOW}◆ Checking port availability...${NC}"

DASHBOARD_PORT=$DEFAULT_DASHBOARD_PORT
API_PORT=$DEFAULT_API_PORT
DAEMON_HEALTH_PORT=$DEFAULT_DAEMON_HEALTH_PORT

if port_in_use $DASHBOARD_PORT; then
    NEW_PORT=$(find_free_port $((DASHBOARD_PORT + 1)))
    if [ -z "$NEW_PORT" ]; then
        echo -e "${RED}  ✗ Cannot find free port for Dashboard${NC}"
        exit 1
    fi
    echo -e "${YELLOW}  ⚠ Port $DASHBOARD_PORT occupied → Dashboard will use port $NEW_PORT${NC}"
    DASHBOARD_PORT=$NEW_PORT
else
    echo -e "${GREEN}  ✓ Dashboard port $DASHBOARD_PORT available${NC}"
fi

if port_in_use $API_PORT; then
    NEW_PORT=$(find_free_port $((API_PORT + 1)))
    if [ -z "$NEW_PORT" ]; then
        echo -e "${RED}  ✗ Cannot find free port for API${NC}"
        exit 1
    fi
    echo -e "${YELLOW}  ⚠ Port $API_PORT occupied → API will use port $NEW_PORT${NC}"
    API_PORT=$NEW_PORT
else
    echo -e "${GREEN}  ✓ API port $API_PORT available${NC}"
fi

if port_in_use $DAEMON_HEALTH_PORT; then
    NEW_PORT=$(find_free_port $((DAEMON_HEALTH_PORT + 1)))
    if [ -z "$NEW_PORT" ]; then
        echo -e "${RED}  ✗ Cannot find free port for Daemon Health${NC}"
        exit 1
    fi
    echo -e "${YELLOW}  ⚠ Port $DAEMON_HEALTH_PORT occupied → Daemon Health will use port $NEW_PORT${NC}"
    DAEMON_HEALTH_PORT=$NEW_PORT
else
    echo -e "${GREEN}  ✓ Daemon Health port $DAEMON_HEALTH_PORT available${NC}"
fi

# =============================================================================
# Step 7: Install and start OmniSec Daemon on host
# =============================================================================
echo ""
echo -e "${YELLOW}◆ Installing OmniSec Daemon on host...${NC}"

# Create a temporary directory for building the daemon
TMP_DAEMON_BUILD=$(mktemp -d)
if git clone https://github.com/manishbalayan/omnisec-v-0.1.git "$TMP_DAEMON_BUILD" 2>/dev/null; then
    echo "  Building OmniSec Daemon..."
    if cd "$TMP_DAEMON_BUILD" && cargo build --release --bin omnisec-daemon; then
        echo -e "${GREEN}  ✓ Daemon built successfully${NC}"
        # Install the daemon binary
        cp "$TMP_DAEMON_BUILD/target/release/omnisec-daemon" /usr/local/bin/
        chmod +x /usr/local/bin/omnisec-daemon
        echo -e "${GREEN}  ✓ Daemon installed to /usr/local/bin/omnisec-daemon${NC}"
        cd -
    else
        echo -e "${RED}  ✗ Failed to build daemon${NC}"
        rm -rf "$TMP_DAEMON_BUILD"
        exit 1
    fi
    rm -rf "$TMP_DAEMON_BUILD"
else
    echo -e "${RED}  ✗ Failed to clone repository for daemon build${NC}"
    exit 1
fi

# Create systemd service file
echo ""
echo -e "${YELLOW}◆ Setting up systemd service...${NC}"
cat > /etc/systemd/system/omnisec-daemon.service << EOF
[Unit]
Description=OmniSec Daemon
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

# Enable and start the service
systemctl daemon-reload
systemctl enable omnisec-daemon
systemctl start omnisec-daemon

# Wait for daemon to be ready
echo ""
echo -e "${YELLOW}◆ Waiting for OmniSec Daemon to start...${NC}"
TIMEOUT=30
ELAPSED=0
while [ ${ELAPSED} -lt ${TIMEOUT} ]; do
    if systemctl is-active --quiet omnisec-daemon; then
        # Additionally check if it's responding on health port
        if nc -z localhost 3003 2>/dev/null; then
            echo -e "${GREEN}  ✓ OmniSec Daemon is ready!${NC}"
            break
        fi
    fi
    sleep 1
    ELAPSED=$((ELAPSED + 1))
    echo -n "."
done
echo ""

if [ ${ELAPSED} -ge ${TIMEOUT} ]; then
    echo -e "${YELLOW}  ⚠ Daemon may still be starting... check status: systemctl status omnisec-daemon${NC}"
fi

# =============================================================================
# Step 8: Start the container (control plane only)
# =============================================================================
echo ""
echo -e "${YELLOW}◆ Starting OmniSec Control Plane (Dashboard, API, PostgreSQL, NATS)...${NC}"

DOCKER_RUN_ARGS=(
    --name "${OMNISEC_CONTAINER_NAME}"
    -p "127.0.0.1:${DASHBOARD_PORT}:3000"
    -p "127.0.0.1:${API_PORT}:3002"
    -p "127.0.0.1:${DAEMON_HEALTH_PORT}:3003"
    -v "${OMNISEC_VOLUME_NAME}:/var/lib/omnisec"
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

# On Linux, mount /proc for agent discovery (needed by dashboard/API for legacy compatibility)
if [ "${OS}" = "Linux" ]; then
    DOCKER_RUN_ARGS+=(-v /proc:/host/proc:ro)
fi

# Start the container
if docker run "${DOCKER_RUN_ARGS[@]}" "${OMNISEC_IMAGE}:${OMNISEC_TAG}" 2>&1; then
    echo -e "${GREEN}  ✓ Control Plane started${NC}"
else
    echo -e "${RED}  ✗ Failed to start Control Plane${NC}"
    echo ""
    echo "  Check Docker logs: docker logs ${OMNISEC_CONTAINER_NAME}"
    exit 1
fi

# =============================================================================
# Step 8: Wait for container to be healthy
# =============================================================================
echo ""
echo -e "${YELLOW}◆ Waiting for OmniSec to start...${NC}"

TIMEOUT=90
ELAPSED=0
while [ ${ELAPSED} -lt ${TIMEOUT} ]; do
    HEALTH=$(docker inspect --format='{{.State.Health.Status}}' "${OMNISEC_CONTAINER_NAME}" 2>/dev/null || echo "starting")
    if [ "${HEALTH}" = "healthy" ]; then
        echo -e "${GREEN}  ✓ OmniSec is ready!${NC}"
        break
    fi
    sleep 2
    ELAPSED=$((ELAPSED + 2))
    echo -n "."
done
echo ""

if [ ${ELAPSED} -ge ${TIMEOUT} ]; then
    echo -e "${YELLOW}  ⚠ Still starting... check logs: docker logs ${OMNISEC_CONTAINER_NAME}${NC}"
fi

# =============================================================================
# Step 9: Get API key from container
# =============================================================================
API_KEY=$(docker exec "${OMNISEC_CONTAINER_NAME}" cat /var/lib/omnisec/.api_key 2>/dev/null || echo "See container logs")

# =============================================================================
# Step 10: Open dashboard
# =============================================================================
API_URL="http://localhost:${API_PORT}"
echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  OmniSec is running!${NC}"
echo ""
echo -e "  Dashboard:  ${BLUE}http://localhost:${DASHBOARD_PORT}${NC}"
echo -e "  API:        ${BLUE}${API_URL}${NC}"
echo -e "  Daemon Health: ${BLUE}http://localhost:${DAEMON_HEALTH_PORT}/health${NC}"
echo -e "  API Key:    ${YELLOW}${API_KEY}${NC}"
echo ""
echo -e "  Commands:"
echo -e "    View logs:     ${BLUE}docker logs -f ${OMNISEC_CONTAINER_NAME}${NC}"
echo -e "    Stop:          ${BLUE}docker stop ${OMNISEC_CONTAINER_NAME}${NC}"
echo -e "    Start:         ${BLUE}docker start ${OMNISEC_CONTAINER_NAME}${NC}"
echo -e "    Remove:        ${BLUE}docker rm -f ${OMNISEC_CONTAINER_NAME}${NC}"
echo ""
echo -e "  Upgrade:"
echo -e "    ${BLUE}docker pull ${OMNISEC_IMAGE}:${OMNISEC_TAG}${NC}"
echo -e "    ${BLUE}docker stop ${OMNISEC_CONTAINER_NAME} && docker rm ${OMNISEC_CONTAINER_NAME}${NC}"
echo -e "    Then re-run this installer."
echo ""
echo -e "  Visit ${BLUE}https://omnisec.ai/docs${NC} for documentation."
echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
echo ""

# Try to open the dashboard in the browser
case "${OS}" in
    Linux)
        if command -v xdg-open &>/dev/null; then
            xdg-open "http://localhost:${DASHBOARD_PORT}" 2>/dev/null || true
        fi
        ;;
    Darwin)
        open "http://localhost:${DASHBOARD_PORT}" 2>/dev/null || true
        ;;
esac
