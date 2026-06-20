# Omnisec

Runtime Control Plane for Autonomous AI Agents.

## Overview

Omnisec sits below AI agents and their harnesses at the operating system and network layers, providing reliability, security, and intelligence for autonomous AI systems.

## Architecture

- **Sensor**: eBPF-based process and network monitoring
- **Daemon**: Core orchestration service
- **API**: REST API for dashboard and management
- **Proxy**: Transparent proxy for AI model requests
- **Policy Engine**: YAML-driven policy enforcement
- **Dashboard**: Next.js web interface

## Quick Start

### Prerequisites

- Docker and Docker Compose
- Rust toolchain (for development)

### Development

```bash
# Start infrastructure
docker-compose -f infra/docker/docker-compose.yml up -d

# Run API server
cargo run --bin omnisec-api

# Run daemon
cargo run --bin omnisec-daemon

# Run dashboard
cd apps/dashboard && npm install && npm run dev
```

### Production

```bash
docker-compose -f infra/docker/docker-compose.yml up --build
```

## Configuration

Environment variables:

- `DATABASE_URL`: PostgreSQL connection string
- `REDIS_URL`: Redis connection string
- `NATS_URL`: NATS connection string
- `TELEGRAM_BOT_TOKEN`: Telegram bot token for alerts
- `TELEGRAM_CHAT_ID`: Telegram chat ID for alerts

## License

MIT
