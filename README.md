# Omnisec

Runtime Control Plane for Autonomous AI Agents.

## Overview

Omnisec sits below AI agents and their harnesses at the operating system and
network layers, providing reliability, security, and intelligence for
autonomous AI systems.

Omnisec is **host-native infrastructure software** — it installs and runs
directly on the operating system as native services (systemd on Linux, launchd
on macOS), the same way Datadog Agent, Tailscale, or the Elastic Agent do.
**There is no Docker and no container runtime anywhere in the product.**

## Architecture

```
Host OS (Linux: systemd  |  macOS: launchd)
├── omnisec-postgres     state store          (127.0.0.1:5432)
├── omnisec-nats         event bus, JetStream (127.0.0.1:4222)
├── omnisec-daemon       core product — discovery, health, restart, enforcement
├── omnisec-api          read-only REST API   (127.0.0.1:3002)
└── omnisec-dashboard    Next.js web UI       (127.0.0.1:3000)
```

- **Daemon**: the core product — agent discovery, health monitoring, hang/crash
  detection, automatic restart, security analysis, and kernel-level enforcement.
  Runs as root and uses native OS capabilities directly: `/proc`, eBPF, nftables,
  cgroups, inotify, ptrace (Linux); sysctl, pf, kqueue (macOS).
- **API**: read-only REST API serving the dashboard.
- **Dashboard**: Next.js web interface.

All services communicate over the loopback interface only.

## Quick Start

### Installation

```bash
curl -fsSL https://raw.githubusercontent.com/manishbalayan/omnisec-v-0.1/main/deploy/install.sh | sudo sh
```

This single command:

1. Detects your OS and architecture
2. Creates a dedicated `omnisec` service user
3. Installs PostgreSQL and NATS natively (via your package manager / Homebrew)
4. Downloads the OmniSec binaries and dashboard bundle from GitHub Releases
5. Initializes the database and writes configuration to `/etc/omnisec/omnisec.env`
6. Registers and starts native services (systemd units / launchd plists)
7. Verifies every service and prints access URLs

No Docker, no containers, no manual setup.

### Prerequisites

- **curl** (pre-installed on most systems)
- **root** (run the installer with `sudo`)
- On macOS: **Homebrew** (used to install PostgreSQL and NATS)

PostgreSQL and NATS are installed automatically if not already present.

### Platform Support

| Platform | Architecture | Service manager | Support |
|----------|-------------|-----------------|---------|
| Linux | x86_64 (amd64) | systemd | ✅ |
| Linux | aarch64 (arm64) | systemd | ✅ |
| macOS Intel | x86_64 (amd64) | launchd | ✅ |
| macOS Apple Silicon | aarch64 (arm64) | launchd | ✅ |

### Managing services

**Linux (systemd):**
```bash
sudo systemctl status omnisec-daemon
sudo journalctl -u omnisec-daemon -f
sudo systemctl stop omnisec.target      # stop everything
sudo omnisec-doctor                     # health diagnostics
```

**macOS (launchd):**
```bash
sudo launchctl print system/com.omnisec.daemon
tail -f /usr/local/var/log/omnisec/daemon.log
sudo omnisec-doctor
```

### Uninstall

```bash
sudo sh deploy/install.sh --uninstall
```

## Development

```bash
# Build all binaries
cargo build --release --bin omnisec-daemon --bin omnisec-api --bin omnisec-doctor

# Install everything host-natively from a source checkout (builds + registers services)
sudo sh deploy/install.sh --build

# Run the dashboard in dev mode
cd apps/dashboard && npm install && npm run dev
```

For local iteration you need PostgreSQL and NATS running on loopback. The
installer sets these up; alternatively start your own and point the binaries at
them via `DATABASE_URL` / `NATS_URL`.

## Configuration

All configuration lives in a single env file (`/etc/omnisec/omnisec.env` on
Linux, `/usr/local/etc/omnisec/omnisec.env` on macOS), sourced by every service:

- `DATABASE_URL` — PostgreSQL connection string (loopback)
- `NATS_URL` — NATS connection string (loopback)
- `API_BIND` / `DAEMON_HEALTH_BIND` / `DASHBOARD_PORT` — service bind addresses
- `OMNISEC_API_KEY` — API authentication key (generated at install)
- `OMNISEC_SAFE_MODE` / `OMNISEC_RECOMMENDATION_ONLY` — enforcement gating
- `TELEGRAM_BOT_TOKEN` / `TELEGRAM_CHAT_ID` — optional Telegram alerting
- `RUST_LOG` — log level

## License

MIT
