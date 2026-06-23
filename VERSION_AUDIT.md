# Omnisec v0.1.0 — Version Audit

Generated: 2026-06-20
Git Tag: v0.1.0

---

## Codebase Structure

| Category | Count |
|---|---|
| **Total Rust crates** | 25 |
| **Total services** | 5 |
| **Total apps** | 2 |
| **Database migrations** | 5 |
| **Dockerfiles** | 6 |
| **Config files (yml/yaml)** | 2 |
| **Total source files (.rs)** | 70 |
| **Total test files (.rs)** | 19 |
| **Total files copied** | 158 |
| **Total folders copied** | 102 |
| **Snapshot size (excl. build artifacts)** | 1.5 MB |

---

## Crate Inventory (25 crates)

| Crate | Purpose | Tests |
|---|---|---|
| `omnisec-alerts` | Telegram/Slack/Email alert dispatch | 3 |
| `omnisec-anomaly` | 6-type anomaly detection with baseline gating | 9 |
| `omnisec-chaos` | Process chaos scenarios for testing | 0 |
| `omnisec-decision` | Policy evaluation engine + human overrides | 10 |
| `omnisec-discovery` | Multi-platform AI agent scanner | 4 |
| `omnisec-ebpf` | eBPF userspace loader + `/proc` fallback | 0 |
| `omnisec-ebpf-bpf` | eBPF kernel tracepoint programs | 0 |
| `omnisec-ebpf-common` | Shared event types for kernel/userspace | 0 |
| `omnisec-enforcement` | Userspace enforcement + incident tracking | 9 |
| `omnisec-events` | Event envelope types + NATS subject constants | 4 |
| `omnisec-fingerprint` | Versioned behavioral fingerprinting + drift | 7 |
| `omnisec-identity` | PID → agent identity resolution | 0 |
| `omnisec-intelligence` | Cost dashboard + model recommendations | 0 |
| `omnisec-messaging` | NATS client wrapper with typed pub/sub | 0 |
| `omnisec-metrics` | Metrics primitives | 0 |
| `omnisec-models` | Shared domain models (Agent, Event, Policy) | 0 |
| `omnisec-monitoring` | Health FSM + restart engine | 3 |
| `omnisec-network` | Network connection tracking + traffic stats | 7 |
| `omnisec-reliability` | Reliability metrics + incident engine | 12 |
| `omnisec-restart` | Async restart orchestration | 0 |
| `omnisec-runtime` | Linux runtime control (signals/nftables/cgroups/inotify) | 4 |
| `omnisec-security` | 5-profile behavioral security + correlation | 17 |
| `omnisec-sensor` | Sensor abstraction layer | 0 |
| `omnisec-storage` | PostgreSQL persistence layer | 0 |
| `omnisec-systemd` | Systemd service control | 0 |

---

## Service Inventory (5 services)

| Service | Binary | Purpose |
|---|---|---|
| `daemon` | `omnisec-daemon` | Core event-driven daemon; 9 async tasks |
| `doctor` | `omnisec-doctor` | Pre-flight system check CLI (10 checks) |
| `support-bundle` | `omnisec-support-bundle` | Diagnostic archive generator |
| `proxy` | `omnisec-proxy` | Provider-agnostic caching proxy + cost tracking |
| `policy-engine` | `omnisec-policy-engine` | Policy management service |

---

## App Inventory (2 apps)

| App | Tech | Purpose |
|---|---|---|
| `api` | Axum 0.7 (Rust) | REST API — 28 endpoints, static key auth |
| `dashboard` | Next.js 14 (TypeScript) | Web UI — 4 pages (overview/security/reliability/enforcement) |

---

## Lines of Code Estimate

| Language | LOC |
|---|---|
| Rust (`.rs`) | 25,153 |
| TypeScript / TSX (`.tsx`, `.ts`, `.js`) | 2,370 |
| SQL migrations (`.sql`) | 516 |
| TOML configs (`.toml`) | 610 |
| **Total** | **~28,649** |

---

## Build Result

```
Command:   cargo build --workspace
Directory: ~/Desktop/omnisec-version-0.1
Result:    PASS
Errors:    0
Warnings:  28 (unused imports/variables — non-blocking)
Duration:  8m 38s (cold build, no cache)
Profile:   dev (unoptimized + debuginfo)
```

**Warning categories (non-blocking):**
- Unused imports in 8 crates
- Unused variables in `crates/runtime/src/process.rs` (`agent_name` parameter)
- Future-incompatibility note: `sqlx-postgres v0.7.4` (upgrade path available)

---

## Test Result

```
Command:   cargo test --workspace --lib
Directory: ~/Desktop/omnisec-version-0.1
Result:    PASS
Passed:    95
Failed:    0
Ignored:   1 (final_alpha_audit_report — requires --ignored flag)
Skipped:   0
```

**Tests by crate:**

| Crate | Tests | Result |
|---|---|---|
| omnisec-alerts | 3 | PASS |
| omnisec-anomaly | 9 | PASS |
| omnisec-decision | 10 | PASS |
| omnisec-discovery | 4 | PASS |
| omnisec-enforcement | 9 | PASS |
| omnisec-events | 4 | PASS |
| omnisec-fingerprint | 7 | PASS |
| omnisec-monitoring | 3 | PASS |
| omnisec-network | 7 | PASS |
| omnisec-reliability | 12 | PASS |
| omnisec-runtime | 4 | PASS |
| omnisec-security | 17 | PASS |
| omnisec-proxy (cost) | 4 | PASS |

| **Total** | **95** | **ALL PASS** |

**Integration tests (not run — require live infrastructure):**
- `tests/integration/` — control_loop, scenarios (require PostgreSQL + NATS)

---

## Git Tag

```
Tag:     v0.1.0
Message: v0.1.0 — Design Partner Edition — 2026-06-20
Commit:  03840e5
Branch:  master
```

---

## Snapshot Verification Checksums

```
Source:       ~/Desktop/omnisec
Destination:  ~/Desktop/omnisec-version-0.1
Method:       rsync -a (preserves permissions, symlinks, hidden files)
Excluded:     target/, node_modules/, .next/, *.tmp
Files copied: 158
Dirs copied:  102
Build:        PASS
Tests:        PASS (95/95)
Tag:          v0.1.0 applied
```

---

*This file was generated automatically as part of the v0.1.0 release freeze process.*
*The snapshot at `~/Desktop/omnisec-version-0.1` is frozen. All development continues in `~/Desktop/omnisec`.*
