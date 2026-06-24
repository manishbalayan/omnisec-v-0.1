#!/bin/bash
# =============================================================================
# OmniSec Entrypoint
# =============================================================================
# Runs inside the all-in-one container on every startup.
#
# Flow:
#   1. Generate API key if not set (persisted to data volume)
#   2. Initialize PostgreSQL data directory on first run
#   3. Start PostgreSQL
#   4. Create database and user
#   5. Start NATS
#   6. Run migrations
#   7. Start OmniSec services via supervisor
#   8. Print dashboard URL
#
# User never needs to configure anything. Data persists across restarts.
# =============================================================================

set -e

export OMNISEC_DATA_DIR="${OMNISEC_DATA_DIR:-/var/lib/omnisec}"
export OMNISEC_PGBIN="${OMNISEC_PGBIN:-/usr/lib/postgresql/16/bin}"
POSTGRES_DATA="${OMNISEC_DATA_DIR}/postgres"
POSTGRES_LOG="${OMNISEC_DATA_DIR}/logs/postgres.log"
INFRA_LOG="${OMNISEC_DATA_DIR}/logs/infrastructure.log"

# =============================================================================
# Signal handling — forward to supervisor for clean shutdown
# =============================================================================
cleanup() {
    echo "[omnisec] Shutting down..."
    if [ -f /tmp/supervisord.pid ]; then
        supervisorctl stop all 2>/dev/null || true
        kill $(cat /tmp/supervisord.pid) 2>/dev/null || true
    fi
    su - postgres -c "${OMNISEC_PGBIN}/pg_ctl stop -D ${POSTGRES_DATA} -m fast" 2>/dev/null || true
    kill %1 2>/dev/null || true  # NATS
    exit 0
}
trap cleanup SIGTERM SIGINT SIGQUIT

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  OmniSec Reliability v0.1"
echo "═══════════════════════════════════════════════════════════════"
echo ""

# =============================================================================
# Step 1: Generate API key
# =============================================================================
if [ -z "$OMNISEC_API_KEY" ]; then
    if [ -f "${OMNISEC_DATA_DIR}/.api_key" ]; then
        export OMNISEC_API_KEY=$(cat "${OMNISEC_DATA_DIR}/.api_key")
        echo "[omnisec] ✓ Restored API key from volume"
    else
        export OMNISEC_API_KEY="omnisec-$(date +%s)-$(openssl rand -hex 16 2>/dev/null || head -c16 /dev/urandom | od -An -tx1 | tr -d ' ')"
        echo "$OMNISEC_API_KEY" > "${OMNISEC_DATA_DIR}/.api_key"
        chmod 600 "${OMNISEC_DATA_DIR}/.api_key"
        echo "[omnisec] ✓ Generated API key: ${OMNISEC_API_KEY}"
    fi
else
    echo "$OMNISEC_API_KEY" > "${OMNISEC_DATA_DIR}/.api_key"
    chmod 600 "${OMNISEC_DATA_DIR}/.api_key"
    echo "[omnisec] ✓ Using provided API key"
fi

# =============================================================================
# Step 2: Initialize PostgreSQL on first run
# =============================================================================
# Ensure socket, data, and logs directories exist with correct ownership
mkdir -p /var/run/postgresql
chown postgres:postgres /var/run/postgresql
mkdir -p "${POSTGRES_DATA}"
mkdir -p "${OMNISEC_DATA_DIR}/logs"
chown -R postgres:postgres "${OMNISEC_DATA_DIR}"

if [ ! -f "${POSTGRES_DATA}/PG_VERSION" ]; then
    echo "[omnisec] ◆ Initializing PostgreSQL (first run)..."

    su - postgres -c "${OMNISEC_PGBIN}/initdb -D ${POSTGRES_DATA} --auth=trust --no-instructions >> ${POSTGRES_LOG} 2>&1"

    # Configure PostgreSQL
    cat >> "${POSTGRES_DATA}/postgresql.conf" <<-EOCONF
listen_addresses = 'localhost'
port = 5432
unix_socket_directories = '/var/run/postgresql'
max_connections = 50
shared_buffers = 128MB
EOCONF

    echo "[omnisec] ✓ PostgreSQL initialized"
else
    echo "[omnisec] ✓ PostgreSQL data directory exists"
fi

# =============================================================================
# Step 3: Start PostgreSQL
# =============================================================================
echo "[omnisec] ◆ Starting PostgreSQL..."
su - postgres -c "${OMNISEC_PGBIN}/pg_ctl start -D ${POSTGRES_DATA} -l ${POSTGRES_LOG} -w >> ${POSTGRES_LOG} 2>&1"

# Wait for PostgreSQL
for i in $(seq 1 30); do
    if su - postgres -c "${OMNISEC_PGBIN}/pg_isready -q" 2>/dev/null; then
        echo "[omnisec] ✓ PostgreSQL ready"
        break
    fi
    if [ "$i" -eq 30 ]; then
        echo "[omnisec] ✗ PostgreSQL failed to start. Check ${POSTGRES_LOG}"
        exit 1
    fi
    sleep 1
done

# =============================================================================
# Step 4: Create database and user
# =============================================================================
echo "[omnisec] ◆ Ensuring database and user..."
su - postgres -c "${OMNISEC_PGBIN}/psql -tAc \"SELECT 1 FROM pg_roles WHERE rolname='omnisec'\"" 2>/dev/null | grep -q 1 || \
    su - postgres -c "${OMNISEC_PGBIN}/createuser omnisec"
su - postgres -c "${OMNISEC_PGBIN}/psql -tAc \"SELECT 1 FROM pg_database WHERE datname='omnisec'\"" 2>/dev/null | grep -q 1 || \
    su - postgres -c "${OMNISEC_PGBIN}/createdb omnisec -O omnisec"
su - postgres -c "${OMNISEC_PGBIN}/psql -c \"ALTER USER omnisec WITH PASSWORD 'omnisec';\"" 2>/dev/null
echo "[omnisec] ✓ Database ready"

# =============================================================================
# Step 5: Start NATS
# =============================================================================
echo "[omnisec] ◆ Starting NATS..."
nats-server -js --port 4222 --http_port 8222 --store_dir "${OMNISEC_DATA_DIR}/nats" \
    >> "${OMNISEC_DATA_DIR}/logs/nats.log" 2>&1 &
NATS_PID=$!

for i in $(seq 1 15); do
    if nc -z localhost 4222 2>/dev/null; then
        echo "[omnisec] ✓ NATS ready"
        break
    fi
    sleep 1
done

# =============================================================================
# Step 6: Run migrations
# =============================================================================
echo "[omnisec] ◆ Running database migrations..."
if command -v omnisec-doctor &>/dev/null; then
    # Run doctor to verify connectivity and run migrations
    # The API service also runs migrations on startup via Storage::run_migrations()
    if timeout 30 omnisec-doctor 2>&1 | sed 's/^/[omnisec]   /'; then
        echo "[omnisec] ✓ Doctor check passed"
    else
        echo "[omnisec] ⚠ Doctor check skipped or failed (migrations will run when API starts)"
    fi
fi
echo "[omnisec] ✓ Database ready for migrations"

# =============================================================================
# Step 7: Verify connectivity
# =============================================================================
echo "[omnisec] ◆ Verifying service connectivity..."
su - postgres -c "${OMNISEC_PGBIN}/psql -d omnisec -c 'SELECT 1'" > /dev/null 2>&1 && \
    echo "[omnisec]   ✓ Database" || echo "[omnisec]   ✗ Database"
nc -z localhost 4222 > /dev/null 2>&1 && \
    echo "[omnisec]   ✓ NATS" || echo "[omnisec]   ✗ NATS"

# =============================================================================
# Step 8: Print dashboard URL and start OmniSec services
# =============================================================================
# =============================================================================
# Step 8: Patch Dashboard JS bundle with correct API URL
# =============================================================================
# NEXT_PUBLIC_API_URL is baked into the JS bundle at build time. The Dockerfile
# uses a placeholder "http://omnisec-api-placeholder:3002" which we replace here
# with the actual host-facing API URL so client-side fetches reach the correct port.
#
# OMNISEC_API_EXTERNAL_PORT is set by the installer; defaults to 3002.
# =============================================================================
API_EXTERNAL_PORT="${OMNISEC_API_EXTERNAL_PORT:-3002}"

if [ -d "/opt/omnisec-dashboard/.next" ]; then
    # Replace placeholder in all compiled JS files
    PLACEHOLDER="http://omnisec-api-placeholder:3002"
    REPLACEMENT="http://localhost:${API_EXTERNAL_PORT}"
    grep -rl "$PLACEHOLDER" /opt/omnisec-dashboard/.next 2>/dev/null | while read -r file; do
        sed -i "s|$PLACEHOLDER|$REPLACEMENT|g" "$file"
    done
    echo "[omnisec] ✓ Dashboard API URL patched → ${REPLACEMENT}"

    # Also patch the API key placeholder so the dashboard can authenticate
    API_KEY_PLACEHOLDER="omnisec-placeholder-key"
    grep -rl "$API_KEY_PLACEHOLDER" /opt/omnisec-dashboard/.next 2>/dev/null | while read -r file; do
        sed -i "s|$API_KEY_PLACEHOLDER|$OMNISEC_API_KEY|g" "$file"
    done
    echo "[omnisec] ✓ Dashboard API key patched → ${OMNISEC_API_KEY:0:20}..."
fi

# =============================================================================
# Step 9: Print dashboard URL and start OmniSec services
# =============================================================================
HOST_IP="${HOST_IP:-localhost}"
DASHBOARD_PORT="${DASHBOARD_PORT:-3000}"
DAEMON_HEALTH_PORT="${OMNISEC_DAEMON_HEALTH_EXTERNAL_PORT:-3003}"
DASHBOARD_URL="http://${HOST_IP}:${DASHBOARD_PORT}"
echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  OmniSec Reliability v0.1 is running!"
echo ""
echo "  Dashboard:      ${DASHBOARD_URL}"
echo "  API:            http://localhost:${API_EXTERNAL_PORT}"
echo "  Daemon Health:  http://localhost:${DAEMON_HEALTH_PORT}/health"
echo "  API Key:        ${OMNISEC_API_KEY}"
echo ""
echo "  Data persists in: ${OMNISEC_DATA_DIR}"
echo "═══════════════════════════════════════════════════════════════"
echo ""

# Start OmniSec services via supervisor
exec supervisord -c /etc/supervisor/conf.d/omnisec.conf -n
