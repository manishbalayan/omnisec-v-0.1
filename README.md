# Omnisec

Runtime Control Plane for Autonomous AI Agents.

## Overview

Omnisec sits below AI agents and their harnesses at the operating system and network layers, providing reliability, security, and intelligence for autonomous AI systems.

## Architecture

- **Daemon**: Core orchestration service — agent discovery, health monitoring, hang/crash detection, automatic restart
- **API**: REST API for dashboard and management
- **Dashboard**: Next.js web interface

## Quick Start

### Current Installation

```bash
curl -fsSL https://raw.githubusercontent.com/manishbalayan/omnisec-v-0.1/main/deploy/install.sh | sh
```

This single command:
1. Detects your OS and architecture
2. Downloads the correct pre-built binary from GitHub Releases
3. Verifies the SHA256 checksum
4. Installs the daemon with systemd (Linux) or launchd (macOS)
5. Starts the daemon and Docker control plane stack
6. Verifies all services
7. Prints access URLs

No Rust, Cargo, or compilation required.

### Prerequisites

- **curl** (pre-installed on most systems)
- **Docker** (Desktop on macOS, engine on Linux)
  - Linux: `curl -fsSL https://get.docker.com | sh`
  - macOS: https://docs.docker.com/desktop/install/mac-install/

### Platform Support

| Platform | Architecture | Support |
|----------|-------------|---------|
| Linux | x86_64 (amd64) | ✅ |
| Linux | aarch64 (arm64) | ✅ |
| macOS Intel | x86_64 (amd64) | ⚠️ Pre-release — binaries available, testing ongoing |
| macOS Apple Silicon | aarch64 (arm64) | ⚠️ Pre-release — binaries available, testing ongoing |

### Future Installation Endpoint (Planned)

A dedicated install endpoint at `https://install.omnisec.ai` is planned for a future release.

```bash
# 🚧 NOT YET AVAILABLE — this is a future roadmap goal
# curl -fsSL https://install.omnisec.ai | sh
```

The current installation method using the GitHub raw URL (above) is the only supported installation path today.

### Development

```bash
# Start infrastructure (PostgreSQL, NATS)
docker compose -f tests/integration/docker-compose.test.yml up -d postgres nats

# Or use the all-in-one container (recommended):
docker compose -f tests/integration/docker-compose.test.yml up -d omnisec

# Run API server
cargo run --bin omnisec-api

# Run daemon
cargo run --bin omnisec-daemon

# Run dashboard
cd apps/dashboard && npm install && npm run dev
```

## Configuration

Environment variables:

- `DATABASE_URL`: PostgreSQL connection string
- `NATS_URL`: NATS connection string
- `TELEGRAM_BOT_TOKEN`: Telegram bot token for alerts
- `TELEGRAM_CHAT_ID`: Telegram chat ID for alerts

## License

MIT
