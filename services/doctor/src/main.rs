// omnisec doctor — Pre-flight system health checker.
//
// Checks all infrastructure dependencies and reports PASS / WARN / FAIL
// with actionable remediation steps.
//
// Usage:
//   omnisec-doctor                    # check all
//   omnisec-doctor --json             # machine-readable output
//   omnisec-doctor --fix              # print fix commands (doesn't run them)

use std::process::Command;
use std::time::Duration;

#[derive(Debug, Clone, PartialEq)]
enum Status {
    Pass,
    Warn,
    Fail,
}

impl std::fmt::Display for Status {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Status::Pass => write!(f, "PASS"),
            Status::Warn => write!(f, "WARN"),
            Status::Fail => write!(f, "FAIL"),
        }
    }
}

#[derive(Debug)]
struct CheckResult {
    name: String,
    status: Status,
    message: String,
    remediation: Option<String>,
}

impl CheckResult {
    fn pass(name: &str, msg: &str) -> Self {
        Self { name: name.to_string(), status: Status::Pass, message: msg.to_string(), remediation: None }
    }
    fn warn(name: &str, msg: &str, fix: &str) -> Self {
        Self { name: name.to_string(), status: Status::Warn, message: msg.to_string(), remediation: Some(fix.to_string()) }
    }
    fn fail(name: &str, msg: &str, fix: &str) -> Self {
        Self { name: name.to_string(), status: Status::Fail, message: msg.to_string(), remediation: Some(fix.to_string()) }
    }
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let json_mode = args.iter().any(|a| a == "--json");
    let fix_mode = args.iter().any(|a| a == "--fix");

    if !json_mode {
        println!("╔══════════════════════════════════════════════════════╗");
        println!("║              omnisec doctor                           ║");
        println!("║        Pre-flight system health checker               ║");
        println!("╚══════════════════════════════════════════════════════╝");
        println!();
    }

    let mut results: Vec<CheckResult> = Vec::new();

    // Run all checks
    results.push(check_postgres().await);
    results.push(check_nats().await);
    results.push(check_nftables());
    results.push(check_systemd());
    results.push(check_linux_capabilities());
    results.push(check_kernel_version());
    results.push(check_proc_access());
    results.push(check_disk_space());
    results.push(check_env_vars());

    if json_mode {
        let json: Vec<serde_json::Value> = results.iter().map(|r| {
            serde_json::json!({
                "name": r.name,
                "status": r.status.to_string(),
                "message": r.message,
                "remediation": r.remediation,
            })
        }).collect();
        println!("{}", serde_json::to_string_pretty(&json).unwrap_or_default());
        std::process::exit(if has_failures(&results) { 1 } else { 0 });
    }

    // Pretty print
    for r in &results {
        let icon = match r.status {
            Status::Pass => "✓",
            Status::Warn => "⚠",
            Status::Fail => "✗",
        };
        let color = match r.status {
            Status::Pass => "\x1b[32m",
            Status::Warn => "\x1b[33m",
            Status::Fail => "\x1b[31m",
        };
        let reset = "\x1b[0m";
        println!("  {} {}{}{} {:30} {}", icon, color, r.status, reset, r.name, r.message);
    }

    println!();

    let fails: Vec<_> = results.iter().filter(|r| r.status == Status::Fail).collect();
    let warns: Vec<_> = results.iter().filter(|r| r.status == Status::Warn).collect();

    if !fails.is_empty() || !warns.is_empty() {
        println!("REMEDIATION STEPS:");
        println!("──────────────────");
        for r in fails.iter().chain(warns.iter()) {
            if let Some(ref fix) = r.remediation {
                println!("  [{}] {}", r.name, r.message);
                if fix_mode {
                    println!("    $ {}", fix);
                } else {
                    println!("    Fix: {}", fix);
                }
                println!();
            }
        }
    }

    let pass_count = results.iter().filter(|r| r.status == Status::Pass).count();
    let warn_count = warns.len();
    let fail_count = fails.len();

    println!("─────────────────────────────────────────────────────");
    println!("  {} passed  {} warnings  {} failures", pass_count, warn_count, fail_count);

    if fail_count > 0 {
        println!("\n  ✗ Omnisec is NOT ready to start. Fix failures above.");
        std::process::exit(1);
    } else if warn_count > 0 {
        println!("\n  ⚠ Omnisec can start but some features may be degraded.");
        std::process::exit(0);
    } else {
        println!("\n  ✓ All checks passed. Omnisec is ready.");
        std::process::exit(0);
    }
}

fn has_failures(results: &[CheckResult]) -> bool {
    results.iter().any(|r| r.status == Status::Fail)
}

// ── Individual checks ────────────────────────────────────────────────────────

async fn check_postgres() -> CheckResult {
    let url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:postgres@localhost:5432/omnisec".to_string());

    // Extract host:port from the URL
    let addr = extract_host_port(&url, 5432);
    match tcp_probe(&addr, Duration::from_secs(3)).await {
        Ok(_) => CheckResult::pass("postgres", &format!("reachable at {}", addr)),
        Err(e) => CheckResult::fail(
            "postgres",
            &format!("cannot connect to {}: {}", addr, e),
            "sudo systemctl start omnisec-postgres  (Linux)  OR  sudo launchctl kickstart -k system/com.omnisec.postgres  (macOS)",
        ),
    }
}

async fn check_nats() -> CheckResult {
    let url = std::env::var("NATS_URL")
        .unwrap_or_else(|_| "nats://localhost:4222".to_string());
    let addr = extract_host_port(&url, 4222);
    match tcp_probe(&addr, Duration::from_secs(3)).await {
        Ok(_) => CheckResult::pass("nats", &format!("reachable at {}", addr)),
        Err(e) => CheckResult::fail(
            "nats",
            &format!("cannot connect to {}: {}", addr, e),
            "sudo systemctl start omnisec-nats  (Linux)  OR  sudo launchctl kickstart -k system/com.omnisec.nats  (macOS)",
        ),
    }
}

fn check_nftables() -> CheckResult {
    #[cfg(target_os = "linux")]
    {
        match Command::new("nft").arg("--version").output() {
            Ok(o) if o.status.success() => {
                let version = String::from_utf8_lossy(&o.stdout).trim().to_string();
                // Check if we can list tables (requires CAP_NET_ADMIN)
                match Command::new("nft").args(["list", "tables"]).output() {
                    Ok(o2) if o2.status.success() => {
                        CheckResult::pass("nftables", &format!("{} — kernel rules available", version))
                    }
                    _ => CheckResult::warn(
                        "nftables",
                        "nft installed but insufficient permissions (needs CAP_NET_ADMIN)",
                        "Run daemon with: cap_add: [NET_ADMIN]  or  AmbientCapabilities=CAP_NET_ADMIN",
                    ),
                }
            }
            _ => CheckResult::warn(
                "nftables",
                "nft not found — network blocking will be disabled",
                "apt-get install nftables  OR  yum install nftables",
            ),
        }
    }
    #[cfg(not(target_os = "linux"))]
    CheckResult::warn(
        "nftables",
        "not Linux — nftables unavailable (simulated mode active)",
        "Run Omnisec on Linux for full kernel-level network control",
    )
}

fn check_systemd() -> CheckResult {
    #[cfg(target_os = "linux")]
    {
        match Command::new("systemctl").arg("--version").output() {
            Ok(o) if o.status.success() => {
                CheckResult::pass("systemd", "systemctl available")
            }
            _ => CheckResult::warn(
                "systemd",
                "systemctl not found — systemd integration disabled",
                "Install systemd or use a systemd-compatible init system",
            ),
        }
    }
    #[cfg(not(target_os = "linux"))]
    CheckResult::warn(
        "systemd",
        "not Linux — systemd integration unavailable",
        "Run Omnisec on Linux for systemd service control",
    )
}

fn check_linux_capabilities() -> CheckResult {
    #[cfg(target_os = "linux")]
    {
        // Check if running as root or with required capabilities
        let uid = unsafe { libc::getuid() };
        if uid == 0 {
            return CheckResult::pass("capabilities", "running as root — all capabilities available");
        }

        // Check for /proc/self/status for CapEff
        match std::fs::read_to_string("/proc/self/status") {
            Ok(status) => {
                let cap_eff = status.lines()
                    .find(|l| l.starts_with("CapEff:"))
                    .and_then(|l| l.split_whitespace().nth(1))
                    .and_then(|s| u64::from_str_radix(s, 16).ok())
                    .unwrap_or(0);

                // CAP_NET_ADMIN = bit 12, CAP_SYS_PTRACE = bit 19, CAP_DAC_READ_SEARCH = bit 2
                let has_net_admin = cap_eff & (1 << 12) != 0;
                let has_ptrace = cap_eff & (1 << 19) != 0;
                let has_dac_read = cap_eff & (1 << 2) != 0;

                if has_net_admin && has_ptrace {
                    CheckResult::pass("capabilities", "CAP_NET_ADMIN + CAP_SYS_PTRACE present")
                } else {
                    let missing: Vec<&str> = [
                        (!has_net_admin).then_some("CAP_NET_ADMIN"),
                        (!has_ptrace).then_some("CAP_SYS_PTRACE"),
                        (!has_dac_read).then_some("CAP_DAC_READ_SEARCH"),
                    ].into_iter().flatten().collect();

                    CheckResult::warn(
                        "capabilities",
                        &format!("missing: {}", missing.join(", ")),
                        "Add to systemd unit: AmbientCapabilities=CAP_NET_ADMIN CAP_SYS_PTRACE CAP_DAC_READ_SEARCH",
                    )
                }
            }
            Err(_) => CheckResult::warn(
                "capabilities",
                "cannot read /proc/self/status",
                "Ensure daemon runs on Linux with /proc mounted",
            ),
        }
    }
    #[cfg(not(target_os = "linux"))]
    CheckResult::warn(
        "capabilities",
        "not Linux — capability check skipped",
        "Run Omnisec on Linux for full kernel integration",
    )
}

fn check_kernel_version() -> CheckResult {
    #[cfg(target_os = "linux")]
    {
        match std::fs::read_to_string("/proc/version") {
            Ok(version) => {
                let ver_str = version.trim();
                // Parse major.minor from "Linux version X.Y.Z ..."
                let parts: Vec<u32> = ver_str
                    .split_whitespace()
                    .nth(2)
                    .unwrap_or("0.0")
                    .split('.')
                    .take(2)
                    .filter_map(|s| s.parse().ok())
                    .collect();
                let major = parts.first().copied().unwrap_or(0);
                let minor = parts.get(1).copied().unwrap_or(0);
                let kernel_ver = format!("{}.{}", major, minor);

                if major > 5 || (major == 5 && minor >= 4) {
                    CheckResult::pass("kernel", &format!("{} — inotify + nftables supported", kernel_ver))
                } else {
                    CheckResult::warn(
                        "kernel",
                        &format!("{} — kernel 5.4+ recommended for full inotify/nftables support", kernel_ver),
                        "Upgrade kernel to 5.4+ for full runtime control features",
                    )
                }
            }
            Err(_) => CheckResult::warn(
                "kernel",
                "cannot read /proc/version",
                "Ensure /proc is mounted",
            ),
        }
    }
    #[cfg(not(target_os = "linux"))]
    CheckResult::warn(
        "kernel",
        "not Linux — kernel check skipped",
        "Run Omnisec on Linux kernel 5.4+",
    )
}

fn check_proc_access() -> CheckResult {
    #[cfg(target_os = "linux")]
    {
        match std::fs::read_dir("/proc") {
            Ok(_) => {
                // Try reading a specific process entry
                match std::fs::read_to_string("/proc/1/comm") {
                    Ok(_) => CheckResult::pass("proc", "/proc readable — process discovery enabled"),
                    Err(_) => CheckResult::warn(
                        "proc",
                        "/proc readable but /proc/1/comm inaccessible (limited visibility)",
                        "Run with CAP_SYS_PTRACE or as root for full process visibility",
                    ),
                }
            }
            Err(e) => CheckResult::fail(
                "proc",
                &format!("/proc not accessible: {}", e),
                "Mount /proc: mount -t proc proc /proc",
            ),
        }
    }
    #[cfg(not(target_os = "linux"))]
    CheckResult::warn(
        "proc",
        "not Linux — /proc monitoring unavailable",
        "Run Omnisec on Linux for /proc-based process tracking",
    )
}

fn check_disk_space() -> CheckResult {
    // Check if the data directory has enough space (100MB minimum)
    #[cfg(unix)]
    {
        #[allow(unused_imports)]
        use std::os::unix::fs::MetadataExt;
        let data_dir = std::env::var("OMNISEC_DATA_DIR").unwrap_or_else(|_| "/var/lib/omnisec".to_string());
        let check_dir = if std::path::Path::new(&data_dir).exists() { &data_dir } else { "/tmp" };

        match std::fs::metadata(check_dir) {
            Ok(_) => {
                // Use statvfs-equivalent: df command
                match Command::new("df").args(["-k", check_dir]).output() {
                    Ok(o) => {
                        let out = String::from_utf8_lossy(&o.stdout);
                        let available_kb: u64 = out.lines().nth(1)
                            .and_then(|l| l.split_whitespace().nth(3))
                            .and_then(|s| s.parse().ok())
                            .unwrap_or(u64::MAX);

                        let available_mb = available_kb / 1024;
                        if available_mb > 500 {
                            CheckResult::pass("disk", &format!("{}MB available at {}", available_mb, check_dir))
                        } else if available_mb > 100 {
                            CheckResult::warn(
                                "disk",
                                &format!("only {}MB available at {} — logs may fill disk", available_mb, check_dir),
                                "Free disk space or configure log rotation",
                            )
                        } else {
                            CheckResult::fail(
                                "disk",
                                &format!("critically low disk: {}MB at {}", available_mb, check_dir),
                                "Free at least 100MB of disk space",
                            )
                        }
                    }
                    Err(_) => CheckResult::warn("disk", "cannot determine disk space", "Check disk manually: df -h"),
                }
            }
            Err(_) => CheckResult::warn(
                "disk",
                &format!("{} does not exist — creating it", data_dir),
                &format!("mkdir -p {} && chown omnisec:omnisec {}", data_dir, data_dir),
            ),
        }
    }
    #[cfg(not(unix))]
    CheckResult::warn("disk", "disk check not supported on this platform", "Check disk manually")
}

fn check_env_vars() -> CheckResult {
    let required = [
        ("DATABASE_URL", "Postgres connection string"),
        ("NATS_URL", "NATS connection string"),
    ];
    let optional = [
        ("OMNISEC_API_KEY", "API authentication key"),
        ("TELEGRAM_BOT_TOKEN", "Telegram alert integration"),
        ("NATS_USER", "NATS authentication username"),
    ];

    let mut missing_required: Vec<&str> = Vec::new();
    let mut missing_optional: Vec<&str> = Vec::new();

    for (var, _) in &required {
        if std::env::var(var).is_err() {
            missing_required.push(var);
        }
    }
    for (var, _) in &optional {
        if std::env::var(var).is_err() {
            missing_optional.push(var);
        }
    }

    if !missing_required.is_empty() {
        CheckResult::fail(
            "env-vars",
            &format!("missing required: {}", missing_required.join(", ")),
            "Set environment variables in .env or systemd unit EnvironmentFile",
        )
    } else if !missing_optional.is_empty() {
        CheckResult::warn(
            "env-vars",
            &format!("missing optional: {} (features disabled)", missing_optional.join(", ")),
            "Set optional env vars to enable integrations",
        )
    } else {
        CheckResult::pass("env-vars", "all required environment variables set")
    }
}

// ── Utilities ────────────────────────────────────────────────────────────────

fn extract_host_port(url: &str, default_port: u16) -> String {
    // Strip scheme (postgres://, nats://)
    let without_scheme = url
        .split("://")
        .nth(1)
        .unwrap_or(url);
    // Strip credentials (user:pass@host:port/db)
    let host_part = without_scheme
        .split('@')
        .last()
        .unwrap_or(without_scheme);
    // Strip path
    let host_port = host_part.split('/').next().unwrap_or(host_part);

    if host_port.contains(':') {
        host_port.to_string()
    } else {
        format!("{}:{}", host_port, default_port)
    }
}

async fn tcp_probe(addr: &str, timeout: Duration) -> std::io::Result<()> {
    match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(addr)).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "connection timed out")),
    }
}

// libc needed only for getuid on Linux
#[cfg(target_os = "linux")]
extern "C" {
    fn getuid() -> u32;
}

#[cfg(target_os = "linux")]
mod libc {
    pub unsafe fn getuid() -> u32 {
        super::getuid()
    }
}
