# OMNISEC eBPF Deployment Guide

## Overview

Omnisec uses Aya (https://aya-rs.dev) to load eBPF programs into the Linux kernel for real-time process, network, and file access monitoring. This replaces polling-based detection with kernel-level telemetry for sub-second detection latency.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                         Userspace                            │
│  ┌──────────────────────────────────────────────────────┐   │
│  │              Omnisec Daemon (Task 9)                  │   │
│  │  ┌──────────────┐  ┌───────────┐  ┌──────────────┐  │   │
│  │  │ EbpfManager  │  │ Identity  │  │   NATS Pub   │  │   │
│  │  │ (Aya loader) │─▶│  Engine   │──▶│ (events)     │  │   │
│  │  └──────┬───────┘  └───────────┘  └──────────────┘  │   │
│  └─────────┼────────────────────────────────────────────┘   │
└────────────┼────────────────────────────────────────────────┘
             │ Ring Buffer (mmap'd shared memory)
┌────────────┼────────────────────────────────────────────────┐
│  ┌─────────▼──────────────────────────────────────────────┐  │
│  │              Linux Kernel (eBPF)                        │  │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐  │  │
│  │  │ Process  │ │ Network  │ │  File    │ │   DNS    │  │  │
│  │  │Sensor    │ │ Sensor   │ │ Sensor   │ │  Sensor  │  │  │
│  │  │sched:exec│ │sys_enter │ │sys_enter │ │sys_enter │  │  │
│  │  │sched:exit│ │_connect  │ │_openat   │ │_sendto   │  │  │
│  │  │sys_enter │ │sys_enter │ │sys_enter │ │(port 53) │  │  │
│  │  │_clone    │ │_bind     │ │_unlinkat │ │          │  │  │
│  │  └──────────┘ └──────────┘ └──────────┘ └──────────┘  │  │
│  └────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────┘
```

## Prerequisites

### Kernel Requirements

- **Linux kernel 5.4+** (BPF CO-RE support in 5.7+)
- **CONFIG_DEBUG_INFO_BTF=y** (kernel BTF support)
- **CONFIG_BPF=y**, **CONFIG_BPF_SYSCALL=y**
- For tracepoints: **CONFIG_FTRACE_SYSCALLS=y**

Check kernel BTF support:
```bash
ls /sys/kernel/btf/vmlinux || echo "BTF not available"
```

### Required Linux Capabilities

The daemon requires these capabilities to load eBPF programs:

| Capability | Purpose |
|---|---|
| `CAP_BPF` | Load BPF programs, create maps |
| `CAP_PERFMON` | Attach tracepoints and kprobes |
| `CAP_NET_ADMIN` | Network-related BPF operations |
| `CAP_SYS_RESOURCE` | Locked memory for BPF maps |

When running with systemd, add to the unit file:
```
CapabilityBoundingSet=CAP_BPF CAP_PERFMON CAP_NET_ADMIN CAP_SYS_RESOURCE
AmbientCapabilities=CAP_BPF CAP_PERFMON CAP_NET_ADMIN CAP_SYS_RESOURCE
```

When running in Docker, add:
```bash
docker run --cap-add=BPF --cap-add=PERFMON --cap-add=NET_ADMIN ...
```

## Installation

### 1. Install BPF toolchain

The eBPF programs are written in Rust via Aya and compile to `bpfel-unknown-none` target.

```bash
# Install bpf-linker (Rust BPF linker)
cargo install bpf-linker

# Add the BPF target
rustup target add bpfel-unknown-none
```

### 2. Build the BPF programs

```bash
# Build the BPF kernel programs (requires bpf-linker)
cargo build --target bpfel-unknown-none -p omnisec-ebpf-bpf

# Build the userspace loader (standard host target)
cargo build -p omnisec-ebpf
cargo build -p omnisec-daemon
```

The compiled BPF bytecode will be at:
```
target/bpfel-unknown-none/debug/omnisec-ebpf-bpf
```

This is embedded into the `omnisec-ebpf` binary at compile time via `include_bytes!`.

### 3. Deploy the daemon

```bash
# Copy artifacts to target system
scp target/debug/omnisec-daemon user@host:/usr/local/bin/

# Create systemd service
cat > /etc/systemd/system/omnisec-daemon.service << 'EOF'
[Unit]
Description=Omnisec Security Daemon
After=network.target nats.service

[Service]
Type=notify
ExecStart=/usr/local/bin/omnisec-daemon
Environment=RUST_LOG=omnisec_daemon=info
CapabilityBoundingSet=CAP_BPF CAP_PERFMON CAP_NET_ADMIN CAP_SYS_RESOURCE
AmbientCapabilities=CAP_BPF CAP_PERFMON CAP_NET_ADMIN CAP_SYS_RESOURCE
WatchdogSec=30
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable omnisec-daemon
systemctl start omnisec-daemon
```

## Fallback Behavior

When eBPF is unavailable (macOS, old kernel, no CAP_BPF), the system falls back to /proc polling:

| Feature | eBPF Mode | Fallback Mode |
|---|---|---|
| Process exec | Real-time (tracepoint) | 1s /proc scan diff |
| Process exit | Real-time (tracepoint) | 1s /proc scan diff |
| Network connect | Real-time (kprobe) | /proc/net/tcp polling |
| File access | Real-time (tracepoint) | inotify (limited) |
| DNS queries | Real-time (kprobe) | Not available |
| Detection latency | <1ms | 1-5 seconds |

## Performance

| Metric | Target | Notes |
|---|---|---|
| CPU overhead | <3% per 100 agents | Ring buffer polling is efficient |
| Memory overhead | <50MB | Mostly BPF maps and ring buffers |
| Event throughput | 100K events/sec | Ring buffer handles burst |
| Detection latency | <1ms | Kernel tracepoint to NATS |
| Max connections | 65,536 | Per ring buffer map |

### Tuning

Adjust ring buffer sizes in `crates/ebpf-bpf/src/lib.rs`:
```rust
#[ring_buf]
pub static PROCESS_EVENTS: RingBuf<ProcessEvent> = RingBuf::new(0);
// Default size is 256 pages (~1MB)
```

## Troubleshooting

### eBPF programs fail to load

```bash
# Check kernel BTF
ls /sys/kernel/btf/vmlinux

# Check capabilities
cat /proc/$(pidof omnisec-daemon)/status | grep CapEff
capsh --decode=$(cat /proc/$(pidof omnisec-daemon)/status | grep CapEff | awk '{print $2}')

# Check kernel config
zcat /proc/config.gz 2>/dev/null | grep -E "BPF|BTF"
```

### BPF program not attaching

```bash
# Check if tracepoints exist
cat /sys/kernel/debug/tracing/available_events | grep -E "sched_process_exec|sys_enter_connect"

# View eBPF debug output
cat /sys/kernel/debug/tracing/trace_pipe
```

### Performance issues

```bash
# Monitor eBPF stats
curl http://localhost:3003/health | jq '.ebpf'

# Check event counts in logs
journalctl -u omnisec-daemon -f | grep "Kernel stream stats"
```

## Supported Distributions

| Distribution | Min Kernel | Notes |
|---|---|---|
| Ubuntu 22.04+ | 5.15 | Full support |
| Ubuntu 24.04 | 6.8 | Full support |
| Debian 12 | 6.1 | Full support |
| RHEL 9 | 5.14 | Full support |
| RHEL 8 | 4.18 | Limited (no BTF) |
| Amazon Linux 2023 | 6.1 | Full support |
| Fedora 38+ | 6.2 | Full support |

## Security Considerations

1. **Capability scoping**: Only `CAP_BPF`, `CAP_PERFMON`, `CAP_NET_ADMIN` are needed — not `CAP_SYS_ADMIN`
2. **Ring buffer isolation**: Each event type has its own ring buffer to prevent cross-contamination
3. **No C code**: Pure Rust eBPF via Aya — no kernel module compilation
4. **Graceful fallback**: Falls back to /proc monitoring if capabilities are missing
5. **Read-only**: eBPF programs capture events only — no kernel modifications
