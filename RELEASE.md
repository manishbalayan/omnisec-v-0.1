# Omnisec v0.1.0 — Design Partner Edition

| Field | Value |
|---|---|
| **Version** | 0.1.0 |
| **Release Name** | Design Partner Edition |
| **Release Date** | 2026-06-20 |
| **Release Type** | Design Partner (not for general sale) |
| **Classification** | Frozen Snapshot — DO NOT MODIFY |

---

## Features Included

### Core Infrastructure
- **NATS Event Bus** — async-nats 0.35, JetStream-compatible, typed publish/subscribe with reconnect
- **PostgreSQL Persistence** — SQLx 0.7, 5 migrations (001–005), organization-scoped schema

### Detection & Monitoring
- **Discovery Engine** — Multi-platform agent scanner; `/proc` on Linux, `ps` on macOS; detects 7 agent frameworks (Claude Code, CrewAI, LangGraph, OpenAI, Docker, Python, Node.js)
- **Monitoring** — Real CPU/memory reads from `/proc`; 5-state health FSM (Unknown→Healthy→Warning→Failed→Restarting); hang detection
- **Restart Engine** — Exponential backoff (2s→300s, max 5 retries); real `Command::spawn()` process restart from cached cmdline

### Security Pipeline
- **Security Pipeline** — 5-signal behavioral profiling: destination/traffic/time/behavior/baseline; 5s continuous loop
- **Fingerprinting** — Versioned behavioral signatures; 4-component drift detection (destinations, ports, traffic, time)
- **Anomaly Detection** — 6 anomaly types: new destination, traffic spike, outbound spike, time anomaly, fingerprint drift, connection spike; Learning/Training/Established gating
- **Correlation Engine** — Multi-agent correlation: shared destinations, global spikes, risk escalation
- **Decision Engine** — 6 default policies; human override system with expiry; policy versioning
- **Enforcement Engine** — Userspace allow/block lists; process executable checking; file access violation tracking; incident management

### Runtime Control (Linux)
- **nftables Integration** — Real `nft` commands via `CAP_NET_ADMIN`; DNS resolution before rule insertion; auto-recovery TTL
- **Process Containment** — Real `SIGSTOP`/`SIGCONT`/`SIGKILL` via `libc::kill`; process quarantine tracking
- **cgroup Throttling** — cgroup v1/v2 CPU+memory limits (best-effort; writes to `/sys/fs/cgroup`)
- **File Monitor** — inotify-based file access monitoring (Linux); pattern matching for sensitive paths
- **Recovery Engine** — In-memory auto-recovery for expired enforcement actions

### eBPF Foundation
- **eBPF Userspace Loader** — Aya-based program loader with graceful `/proc` fallback
- **eBPF Kernel Programs** — Tracepoint programs for execve, connect, openat, unlinkat, sendto (source in `crates/ebpf-bpf`; compilation requires `bpfel-unknown-none` target on Linux)
- **Identity Engine** — PID→agent resolution with process tree tracking

### Intelligence Layer
- **Response Cache (Proxy)** — SHA-256 keyed Redis cache; excludes Authorization header; provider-agnostic
- **Cost Observability** — Per-request token tracking (OpenAI/Anthropic/Gemini layouts); microdollar storage; daily rollup
- **Model Recommendations** — Complexity scoring from proxy-observable signals; human-approval-only (no auto-routing)

### Operations
- **omnisec doctor** — 10 pre-flight system checks; TCP probes; Linux capability detection; `--json` and `--fix` flags
- **omnisec support-bundle** — Diagnostic tar.gz; collects logs, env (secrets redacted), processes, nftables rules, manifest
- **Prometheus Metrics** — `/metrics` endpoint (Prometheus text format; no external crate)
- **Systemd Watchdog** — `NOTIFY_SOCKET` + `WATCHDOG_USEC` integration

### Deployment
- **Design Partner Mode** — `OMNISEC_SAFE_MODE=1`: logs all enforcement, applies none; `OMNISEC_RECOMMENDATION_ONLY=1`: decision engine runs, no kernel actions; `OMNISEC_VERBOSE=1`: extended logging
- **Dashboard** — Next.js 14 with 4 pages: overview, security, reliability, enforcement
- **API** — Axum 0.7; 28 endpoints; static API key authentication
- **All-in-One Deployment** — Single container: PostgreSQL 16, NATS 2, API, Daemon, Dashboard

### Alerting
- **Telegram** — Real Telegram Bot API integration with HTML parse mode
- **Slack** — Real Slack webhook integration
- **Email** — Stub (logs only; SMTP not implemented)

---

## Known Limitations

| Limitation | Impact | Workaround |
|---|---|---|
| **No RBAC** | All authenticated users have full access | Use single shared API key per deployment |
| **No Multi-Tenancy** | DB schema supports it; application enforces single org | One deployment per customer |
| **No SSO** | Static API key only | Rotate key manually |
| **No Billing / Licensing** | No payment infrastructure | Manual invoicing |
| **Stateless Daemon** | Restart wipes all baselines, fingerprints, enforcement state | Minimize daemon restarts; monitor uptime |
| **eBPF Not Compiled** | Falls back to `/proc` polling (1s resolution, no syscall-level data) | Accept `/proc` fallback; plan Linux CI build |
| **nftables Not Bundled** | `nft` command needed for enforcement but not included | Add `nftables` to apt install list in Dockerfile.all-in-one if enforcement is tested |
| **Hardcoded Known Destinations** | 7 entries only; any other AI API produces false positives | Run in SAFE_MODE during baseline period |
| **No cgroup Verification** | CPU/memory limits written but success not confirmed | Monitor `/sys/fs/cgroup` manually |
| **Email Alerts Stub** | Email channel logs but does not send | Use Telegram or Slack |
| **No API Documentation** | No OpenAPI/Swagger spec | Read `apps/api/src/main.rs` |
| **Intelligence Layer Incomplete** | Daily cost rollup requires manual trigger; model catalog is static | Trigger rollup via API manually |
| **Design Partner Release Only** | Not ready for self-service or enterprise deployment | Founder-assisted onboarding required |

---

## Deployment Notes

### Minimum Requirements
- Linux kernel ≥ 5.4 (for inotify + nftables support)
- Docker
- Capabilities: `CAP_NET_ADMIN`, `CAP_SYS_PTRACE`, `CAP_DAC_READ_SEARCH`
- PostgreSQL 16, NATS 2 (bundled in all-in-one image)

### Quick Start (Design Partner)
```bash
# Current installation method (only supported path):
curl -fsSL https://raw.githubusercontent.com/manishbalayan/omnisec-v-0.1/main/deploy/install.sh | sh

# 🚧 Future install endpoint (not yet available):
# curl -fsSL https://install.omnisec.ai | sh
```

Or run directly:
```bash
docker run -d --name omnisec \
  -p 3000:3000 \
  -v omnisec_data:/var/lib/omnisec \
  --restart unless-stopped \
  --cap-add SYS_PTRACE --cap-add NET_ADMIN --cap-add DAC_READ_SEARCH \
  omnisec/omnisec
```

### Recommended Initial Config (Safe Mode)
```bash
OMNISEC_SAFE_MODE=1          # No kernel enforcement — observe only
OMNISEC_RECOMMENDATION_ONLY=1  # Decision engine active; enforcement skipped
OMNISEC_VERBOSE=1            # Extended logging
```

### Build from Source
```bash
cargo build --release
cargo test --workspace --lib
```

---

## Test Coverage

| Suite | Tests | Status |
|---|---|---|
| Unit tests (all crates) | 98 | PASS |
| E2E tests | 30 | #[ignore] — require live infrastructure |
| Integration tests | ~15 | #[ignore] — require live infrastructure |
| Beta audit | 3 | PASS |
| PMF validation | 6 | PASS |

---

## Support

This is a design partner release. Deployment assistance is provided directly by the Omnisec team.

For support, contact the Omnisec team directly. Do not open public issues for design partner deployments.
