# Omnisec

Runtime Control Plane for Autonomous AI Agents.

## Overview

Omnisec sits below AI agents and their harnesses at the operating system and network layers, providing reliability, security, and intelligence for autonomous AI systems.

## Architecture

- **Daemon**: Core orchestration service — agent discovery, health monitoring, hang/crash detection, automatic restart
- **API**: REST API for dashboard and management
- **Dashboard**: Next.js web interface

## Quick Start

### Prerequisites

- Docker

### Installation

```bash
curl -fsSL https://install.omnisec.ai | sh
```

This will pull the all-in-one image, create a persistent data volume, and start all services automatically.

### Or run directly

```bash
docker run -d \
  --name omnisec \
  -p 3000:3000 \
  -v omnisec_data:/var/lib/omnisec \
  --restart unless-stopped \
  --cap-add SYS_PTRACE \
  --cap-add NET_ADMIN \
  --cap-add DAC_READ_SEARCH \
  omnisec/omnisec
```

Then open **http://localhost:3000** in your browser.

### Development

```bash
# Start infrastructure (PostgreSQL, NATS)
docker compose -f tests/integration/docker-compose.test.yml up -d postgres nats

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
