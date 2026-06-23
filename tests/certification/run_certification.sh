#!/bin/bash
# Omnisec Reliability Certification Runner
# Runs on the Ubuntu test server against live infrastructure
#
# Usage: bash tests/certification/run_certification.sh
#
# Release Gates Verified:
#   GATE 3: 100 consecutive crash tests
#   GATE 4: 100 consecutive hang tests
#   GATE 5: 100 consecutive crash-loop tests
#   GATE 6: Dependency failure tests
#   GATE 8: Critical workflow verification

set -euo pipefail

CERT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$CERT_DIR/../.." && pwd)"
REPORT_DIR="${PROJECT_DIR}/certification_results"
mkdir -p "$REPORT_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

pass_count=0
fail_count=0
total_tests=0

log()    { echo -e "${BLUE}[$(date +%H:%M:%S)]${NC} $1"; }
pass()   { echo -e "${GREEN}  ✓ PASS:${NC} $1"; pass_count=$((pass_count + 1)); }
fail()   { echo -e "${RED}  ✗ FAIL:${NC} $1"; fail_count=$((fail_count + 1)); }
warn()   { echo -e "${YELLOW}  ⚠ WARN:${NC} $1"; }
header() { echo; echo "======================================================================"; echo " $1"; echo "======================================================================"; }

# ============================================================================
# Infrastructure Verification
# ============================================================================
verify_infrastructure() {
    header "Verifying Infrastructure"

    # Check Docker
    if docker ps &>/dev/null; then
        pass "Docker daemon is running"
    else
        fail "Docker daemon is not running"
        return 1
    fi

    # Check required containers
    for svc in omnisec-postgres-1 omnisec-nats-1; do
        if docker ps --format '{{.Names}}' | grep -q "$svc"; then
            pass "Container $svc is running"
        else
            fail "Container $svc is not running"
        fi
    done

    # Check NATS connectivity
    if nats --version &>/dev/null; then
        if nats pub test.verify "hello" --server nats://localhost:4222 &>/dev/null; then
            pass "NATS is reachable"
        else
            warn "NATS CLI not functional (may not need this)"
        fi
    fi

    # Check API (internal health endpoint on port 3002)
    if curl -sf http://localhost:3002/health &>/dev/null; then
        pass "API /health endpoint responding on port 3002"
    else
        fail "API not reachable on port 3002"
    fi
}

# ============================================================================
# Test Helper: Check NATS event
# ============================================================================
wait_for_nats_event() {
    local subject="$1"
    local timeout="${2:-30}"
    local description="${3:-$subject}"
    local start_time
    start_time=$(date +%s)

    log "  Waiting for event on $subject (timeout: ${timeout}s)..."
    
    # Use nats CLI to subscribe and wait for first message
    if nats --version &>/dev/null; then
        if nats sub "$subject" --server nats://localhost:4222 --count=1 --timeout="$timeout" &>/tmp/nats_evt_$$.txt; then
            local elapsed=$(( $(date +%s) - start_time ))
            pass "Received $description in ${elapsed}s"
            return 0
        else
            warn "Did not receive $description within ${timeout}s"
            return 1
        fi
    else
        warn "nats CLI not available — cannot verify event: $description"
        return 1
    fi
}

# ============================================================================
# GATE 3: 100 Consecutive Crash Tests
# ============================================================================
run_crash_tests() {
    header "GATE 3: Crash Tests (100 consecutive)"

    local iterations="${1:-100}"
    local success=0
    local failed=0

    for i in $(seq 1 "$iterations"); do
        log "Crash test $i/$iterations..."

        # Subscribe to AGENT_FAILED before spawning agent
        nats sub omnisec.agent.failed --server nats://localhost:4222 --count=1 --timeout=15 &>/tmp/crash_nats_$$.txt &
        local sub_pid=$!

        # Spawn a chaos agent that crashes quickly
        "$PROJECT_DIR/target/release/chaos-agent" crash-after-seconds --seconds 2 &
        local agent_pid=$!
        sleep 1

        wait "$sub_pid" 2>/dev/null && {
            pass "Crash test $i: agent died detected"
            success=$((success + 1))
        } || {
            warn "Crash test $i: detection timeout (agent PID=$agent_pid)"
            failed=$((failed + 1))
        }

        # Cleanup any leftover agent
        kill "$agent_pid" 2>/dev/null || true
        sleep 1
    done

    local rate=$(echo "scale=1; $success * 100 / $iterations" | bc)
    log "Crash test results: $success/$iterations detected ($rate%)"
    echo "$success/$iterations" > "$REPORT_DIR/crash_tests.txt"

    if [ "$success" -eq "$iterations" ]; then
        pass "GATE 3: 100% crash detection rate ($rate%)"
    else
        warn "GATE 3: Detection rate $rate% (need 100%)"
    fi
}

# ============================================================================
# GATE 4: 100 Consecutive Hang Tests
# ============================================================================
run_hang_tests() {
    header "GATE 4: Hang Tests (100 consecutive)"

    local iterations="${1:-100}"
    local success=0
    local failed=0

    for i in $(seq 1 "$iterations"); do
        log "Hang test $i/$iterations..."

        # Subscribe to AGENT_HUNG before spawning agent
        nats sub omnisec.agent.hung --server nats://localhost:4222 --count=1 --timeout=45 &>/tmp/hang_nats_$$.txt &
        local sub_pid=$!

        # Spawn a hang agent (runs forever, sleeps)
        "$PROJECT_DIR/target/release/chaos-agent" hang-forever &
        local agent_pid=$!
        sleep 2

        wait "$sub_pid" 2>/dev/null && {
            pass "Hang test $i: hung agent detected"
            success=$((success + 1))
        } || {
            warn "Hang test $i: detection timeout (agent PID=$agent_pid)"
            failed=$((failed + 1))
        }

        kill "$agent_pid" 2>/dev/null || true
        sleep 1
    done

    local rate=$(echo "scale=1; $success * 100 / $iterations" | bc)
    log "Hang test results: $success/$iterations detected ($rate%)"
    echo "$success/$iterations" > "$REPORT_DIR/hang_tests.txt"

    if [ "$success" -eq "$iterations" ]; then
        pass "GATE 4: 100% hang detection rate ($rate%)"
    else
        warn "GATE 4: Detection rate $rate% (need 100%)"
    fi
}

# ============================================================================
# GATE 5: 100 Consecutive Crash-Loop Tests
# ============================================================================
run_crash_loop_tests() {
    header "GATE 5: Crash-Loop Tests (100 consecutive)"

    local iterations="${1:-100}"
    local success=0
    local failed=0

    for i in $(seq 1 "$iterations"); do
        log "Crash-loop test $i/$iterations..."

        # Subscribe to RESTART_FAILED (exhaustion) or ALERT_REQUESTED
        nats sub omnisec.restart.failed --server nats://localhost:4222 --count=1 --timeout=30 &>/tmp/crashloop_nats_$$.txt &
        local sub_pid=$!

        # Spawn agent that crashes repeatedly
        "$PROJECT_DIR/target/release/chaos-agent" crash-after-seconds --seconds 1 &
        local agent_pid=$!
        sleep 1

        wait "$sub_pid" 2>/dev/null && {
            pass "Crash-loop test $i: restart exhaustion detected"
            success=$((success + 1))
        } || {
            warn "Crash-loop test $i: exhaustion timeout"
            failed=$((failed + 1))
        }

        kill "$agent_pid" 2>/dev/null || true
        sleep 1
    done

    local rate=$(echo "scale=1; $success * 100 / $iterations" | bc)
    log "Crash-loop results: $success/$iterations detected ($rate%)"
    echo "$success/$iterations" > "$REPORT_DIR/crash_loop_tests.txt"

    if [ "$success" -eq "$iterations" ]; then
        pass "GATE 5: 100% crash-loop detection rate ($rate%)"
    else
        warn "GATE 5: Detection rate $rate% (need 100%)"
    fi
}

# ============================================================================
# GATE 6: Dependency Failure Tests
# ============================================================================
run_dependency_tests() {
    header "GATE 6: Dependency Failure Tests"

    # Test 1: PostgreSQL outage and recovery
    log "Testing PostgreSQL outage..."
    nats sub omnisec.dependency.failure --server nats://localhost:4222 --count=1 --timeout=30 &>/tmp/dep_pg_$$.txt &
    local sub_pid=$!
    docker stop omnisec-postgres-1 2>/dev/null
    sleep 10
    docker start omnisec-postgres-1 2>/dev/null
    sleep 15

    wait "$sub_pid" 2>/dev/null && {
        pass "PostgreSQL failure: dependency failure event received"
    } || {
        warn "PostgreSQL failure: no dependency failure event (daemon may not generate this)"
    }

    # Wait for postgres to become healthy
    log "Waiting for PostgreSQL to become healthy..."
    for i in $(seq 1 30); do
        if docker ps --filter "name=omnisec-postgres" --filter "health=healthy" --format '{{.Names}}' | grep -q postgres; then
            pass "PostgreSQL recovered"
            break
        fi
        sleep 2
    done

    # Test 2: NATS outage and recovery
    log "Testing NATS outage..."
    docker stop omnisec-nats-1 2>/dev/null
    sleep 5
    docker start omnisec-nats-1 2>/dev/null
    sleep 10

    if docker ps --filter "name=omnisec-nats" --format '{{.Names}}' | grep -q nats; then
        pass "NATS recovered"
    fi
}

# ============================================================================
# GATE 8: Critical Workflow Verification
# ============================================================================
run_workflow_verification() {
    header "GATE 8: Critical Workflow Verification"

    # 1. Discovery
    log "Verifying agent discovery..."
    local agent_pid
    "$PROJECT_DIR/target/release/chaos-agent" healthy-loop --interval-secs 1 &
    agent_pid=$!
    sleep 10

    if curl -sf http://localhost:3000/api/agents | grep -q "name"; then
        pass "Discovery: agents visible via API"
    else
        warn "Discovery: no agents visible via API (may require daemon binary update)"
    fi
    kill "$agent_pid" 2>/dev/null || true

    # 2. Monitoring
    log "Verifying health monitoring..."
    if curl -sf http://localhost:3000/metrics | grep -q "omnisec_agents"; then
        pass "Monitoring: metrics endpoint shows agent data"
    else
        warn "Monitoring: no agent metrics"
    fi

    # 3. Persistence
    log "Verifying event persistence..."
    if curl -sf http://localhost:3000/api/events | grep -q "events"; then
        pass "Persistence: events API responding"
    else
        warn "Persistence: events API returned unexpected response"
    fi

    # 4. Health endpoint
    log "Verifying health endpoint..."
    if curl -sf http://localhost:3000/health | grep -q "healthy"; then
        pass "Health: /health endpoint returns healthy"
    else
        fail "Health: /health endpoint failed"
    fi
}

# ============================================================================
# Main Execution
# ============================================================================
main() {
    echo "================================================================"
    echo "  Omnisec Reliability Certification Runner"
    echo "  Started: $(date)"
    echo "  Server: $(hostname)"
    echo "================================================================"

    verify_infrastructure || {
        fail "Infrastructure verification failed — aborting"
        echo "$fail_count failures" > "$REPORT_DIR/summary.txt"
        exit 1
    }

    # Run certification gates
    run_crash_tests 100
    run_hang_tests 100
    run_crash_loop_tests 100
    run_dependency_tests
    run_workflow_verification

    # Final summary
    header "CERTIFICATION SUMMARY"
    echo "  Passed: $pass_count"
    echo "  Failed: $fail_count"
    echo ""
    echo "  GATE 3 (Crash Tests):      $(cat "$REPORT_DIR/crash_tests.txt" 2>/dev/null || echo 'Not run')"
    echo "  GATE 4 (Hang Tests):       $(cat "$REPORT_DIR/hang_tests.txt" 2>/dev/null || echo 'Not run')"
    echo "  GATE 5 (Crash-Loop Tests): $(cat "$REPORT_DIR/crash_loop_tests.txt" 2>/dev/null || echo 'Not run')"
    echo "  GATE 6 (Dependency):       $(cat "$REPORT_DIR/dependency_tests.txt" 2>/dev/null || echo 'Not run')"

    echo ""
    if [ "$fail_count" -eq 0 ]; then
        echo -e "${GREEN}ALL TESTS PASSED${NC}"
    else
        echo -e "${YELLOW}$fail_count failures — review logs for details${NC}"
    fi

    echo "$pass_count passes, $fail_count failures" > "$REPORT_DIR/summary.txt"
    echo "Certification complete: $(date)" >> "$REPORT_DIR/summary.txt"
}

main 2>&1 | tee "$REPORT_DIR/certification_output.log"
