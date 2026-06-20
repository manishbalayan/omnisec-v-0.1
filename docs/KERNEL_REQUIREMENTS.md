# OMNISEC Kernel Requirements

## Minimum Kernel Versions

| Feature | Minimum Kernel | Recommended Kernel |
|---|---|---|
| Base eBPF | 4.4 | 5.10+ |
| BPF CO-RE (BTF) | 5.2 | 5.10+ |
| BPF Ring Buffer | 5.8 | 5.15+ |
| BPF Tracepoints | 4.7 | 5.10+ |
| BPF Timestamp | 5.11 | 5.15+ |
| All Omnisec sensors | 5.8 | 6.2+ |

## Required Kernel Configuration

Check your running kernel config:
```bash
# Debian/Ubuntu
cat /boot/config-$(uname -r) | grep -E "CONFIG_BPF|CONFIG_BTF|CONFIG_FTRACE"

# RHEL/Fedora
cat /proc/config.gz | gunzip | grep -E "CONFIG_BPF|CONFIG_BTF|CONFIG_FTRACE"
```

### Mandatory
```
CONFIG_BPF=y
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_JIT=y
CONFIG_DEBUG_INFO_BTF=y         # Required for CO-RE
CONFIG_FTRACE=y
CONFIG_FUNCTION_TRACER=y
CONFIG_HAVE_BPF_JIT=y
```

### For Tracepoint Sensors
```
CONFIG_FTRACE_SYSCALLS=y
CONFIG_HAVE_SYSCALL_TRACEPOINTS=y
```

### For Performance
```
CONFIG_BPF_JIT_ALWAYS_ON=y
CONFIG_BPF_UNPRIV_DEFAULT_OFF=y
```

## Capability Requirements

The Omnisec daemon requires specific Linux capabilities for eBPF operations:

### Minimum Capabilities
```
CAP_BPF       = Load BPF programs, create maps
CAP_PERFMON   = Attach tracepoints and kprobes (was CAP_SYS_ADMIN in older kernels)
CAP_NET_ADMIN = Modify network-related BPF features
```

### Optional Capabilities
```
CAP_SYS_RESOURCE = Increase RLIMIT_MEMLOCK for BPF maps (not needed on 5.11+)
```

### Kernel 5.8+ (Recommended)
- `CAP_BPF`
- `CAP_PERFMON`
- `CAP_NET_ADMIN`

### Kernel 4.x – 5.7 (Legacy Support)
- `CAP_SYS_ADMIN` (required instead of `CAP_BPF` + `CAP_PERFMON`)

## Memory Lock Limits

On kernels before 5.11, BPF requires locked memory. Set the rlimit:

```bash
# System-wide
echo "root soft memlock unlimited" >> /etc/security/limits.conf
echo "root hard memlock unlimited" >> /etc/security/limits.conf

# With systemd service
LimitMEMLOCK=infinity
```

Kernel 5.11+ removed the need for `RLIMIT_MEMLOCK` — BPF uses cgroup memory accounting instead.

## Check Installation

Run the doctor script to verify the system is ready:

```bash
# Check kernel version
uname -r

# Check BTF support
ls /sys/kernel/btf/vmlinux && echo "BTF: OK" || echo "BTF: NOT AVAILABLE"

# Check capabilities support
cat /proc/self/status | grep CapEff

# Check if BPF syscall is available
ls /proc/sys/net/core/bpf_jit_enable && echo "BPF JIT: OK"

# Check tracepoint availability
ls /sys/kernel/debug/tracing/events/syscalls/sys_enter_connect/ && echo "NET connect tracepoint: OK"
ls /sys/kernel/debug/tracing/events/sched/sched_process_exec/ && echo "Exec tracepoint: OK"
ls /sys/kernel/debug/tracing/events/syscalls/sys_enter_openat/ && echo "Openat tracepoint: OK"
```

## Container Environments

### Docker
```dockerfile
FROM ubuntu:24.04
RUN apt-get update && apt-get install -y bpftrace
COPY omnisec-daemon /usr/local/bin/

# Required when running
# docker run --cap-add=BPF --cap-add=PERFMON --cap-add=NET_ADMIN ...
```

### Kubernetes
```yaml
securityContext:
  capabilities:
    add:
      - BPF
      - PERFMON
      - NET_ADMIN
```

**Note**: Some container runtimes (containerd, CRI-O) may need additional seccomp profile configuration.

## Unsupported Configurations

The following configurations are NOT supported for eBPF sensors:

1. **WSL1**: No eBPF support (WSL2 with custom kernel may work)
2. **macOS**: No eBPF support (falls back to /proc simulation mode)
3. **Kernels < 4.4**: No BPF syscall
4. **Kernels without BTF**: CO-RE will not work (can build tailored BPF with BTF dumps)
5. **Flatcar / Bottlerocket**: May need additional kernel modules

## Fallback Strategy

When eBPF is unavailable:
- Omnisec automatically falls back to `/proc` polling for process detection
- Network connections use `/proc/net/tcp` polling
- File monitoring uses inotify (Linux) or is disabled (macOS)
- All core security features continue to work at reduced detection latency (1-5s vs <1ms)
- No user configuration changes needed

## Performance Expectations

### eBPF Mode
| Metric | Expected Value |
|---|---|
| Detection Latency | <100 microseconds |
| CPU per 100 agents | <3% of one core |
| Memory per sensor | ~8MB per ring buffer |
| Event throughput | 100,000+ events/sec |

### Fallback Mode
| Metric | Expected Value |
|---|---|
| Detection Latency | 1-5 seconds |
| CPU per 100 agents | <1% of one core |
| Memory | Negligible |
| Event throughput | Limited by /proc scan speed |
