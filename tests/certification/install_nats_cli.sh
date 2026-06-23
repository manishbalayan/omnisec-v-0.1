#!/bin/bash
# Install NATS CLI on the Ubuntu server for certification testing
set -euo pipefail

echo "Installing NATS CLI..."

# Download the latest nats CLI for linux/arm64
curl -sfL https://github.com/nats-io/natscli/releases/latest/download/nats-0.1.5-linux-arm64.zip -o /tmp/nats.zip 2>/dev/null || {
    # Fallback to a known version
    curl -sfL https://github.com/nats-io/natscli/releases/download/v0.1.5/nats-0.1.5-linux-arm64.zip -o /tmp/nats.zip
}

if [ -f /tmp/nats.zip ]; then
    unzip -o /tmp/nats.zip -d /tmp/nats_extract >/dev/null 2>&1
    sudo cp /tmp/nats_extract/nats-*/nats /usr/local/bin/ 2>/dev/null || sudo cp /tmp/nats_extract/nats /usr/local/bin/
    sudo chmod +x /usr/local/bin/nats
    rm -rf /tmp/nats.zip /tmp/nats_extract
    echo "NATS CLI installed: $(nats --version)"
else
    echo "Could not download NATS CLI — using Docker-based NATS instead"
    echo "Using: docker exec omnisec-nats-1 nats ..."
fi
