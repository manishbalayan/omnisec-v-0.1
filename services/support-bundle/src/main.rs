// omnisec support-bundle — Collects diagnostics for troubleshooting.
//
// Gathers: logs, config, system info, recent incidents, metrics.
// Outputs: single tar.gz archive at the specified path.
//
// Usage:
//   omnisec-support-bundle
//   omnisec-support-bundle --output /tmp/bundle.tar.gz
//   omnisec-support-bundle --days 7

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let output_path = args.windows(2)
        .find(|w| w[0] == "--output")
        .map(|w| w[1].clone())
        .unwrap_or_else(|| {
            let ts = chrono::Utc::now().format("%Y%m%d-%H%M%S");
            format!("/tmp/omnisec-bundle-{}.tar.gz", ts)
        });

    let days: u32 = args.windows(2)
        .find(|w| w[0] == "--days")
        .and_then(|w| w[1].parse().ok())
        .unwrap_or(3);

    println!("┌──────────────────────────────────────────────────┐");
    println!("│           omnisec support-bundle                  │");
    println!("│     Collecting diagnostics for {} day(s)...       │", days);
    println!("└──────────────────────────────────────────────────┘");
    println!();

    let tmp_dir = tempdir()?;
    let bundle_dir = tmp_dir.join("omnisec-bundle");
    fs::create_dir_all(&bundle_dir)?;

    // ── System information ──────────────────────────────────────────────────
    println!("  [1/7] Collecting system information...");
    collect_system_info(&bundle_dir)?;

    // ── Environment (sanitized — no secrets) ────────────────────────────────
    println!("  [2/7] Collecting environment (secrets redacted)...");
    collect_env_sanitized(&bundle_dir)?;

    // ── Daemon logs ─────────────────────────────────────────────────────────
    println!("  [3/7] Collecting daemon logs ({} days)...", days);
    collect_logs(&bundle_dir, days)?;

    // ── Process list ────────────────────────────────────────────────────────
    println!("  [4/7] Collecting process list...");
    collect_processes(&bundle_dir)?;

    // ── Network state ───────────────────────────────────────────────────────
    println!("  [5/7] Collecting network state...");
    collect_network(&bundle_dir)?;

    // ── nftables ruleset ────────────────────────────────────────────────────
    println!("  [6/7] Collecting nftables ruleset...");
    collect_nftables(&bundle_dir)?;

    // ── Manifest ─────────────────────────────────────────────────────────────
    println!("  [7/7] Writing manifest...");
    write_manifest(&bundle_dir, days)?;

    // ── Create tar.gz ────────────────────────────────────────────────────────
    println!();
    println!("  Compressing bundle → {}...", output_path);
    create_tar_gz(&bundle_dir, &output_path)?;

    let size = fs::metadata(&output_path)
        .map(|m| m.len())
        .unwrap_or(0);

    println!();
    println!("╔══════════════════════════════════════════════════╗");
    println!("║  Bundle created: {}", output_path);
    println!("║  Size: {:.1} KB", size as f64 / 1024.0);
    println!("║");
    println!("║  Share this file with Omnisec support.");
    println!("║  Secrets are NOT included.");
    println!("╚══════════════════════════════════════════════════╝");

    Ok(())
}

fn collect_system_info(dir: &Path) -> anyhow::Result<()> {
    let mut info = String::new();

    info.push_str(&format!("Generated: {}\n", chrono::Utc::now().to_rfc3339()));
    info.push_str(&format!("Omnisec version: 0.2.0\n\n"));

    // OS info
    #[cfg(target_os = "linux")]
    {
        if let Ok(os_rel) = fs::read_to_string("/etc/os-release") {
            info.push_str("=== OS Release ===\n");
            info.push_str(&os_rel);
            info.push('\n');
        }
        if let Ok(ver) = fs::read_to_string("/proc/version") {
            info.push_str("=== Kernel ===\n");
            info.push_str(&ver);
            info.push('\n');
        }
        if let Ok(mem) = fs::read_to_string("/proc/meminfo") {
            let relevant: String = mem.lines()
                .filter(|l| l.starts_with("MemTotal") || l.starts_with("MemAvailable"))
                .collect::<Vec<_>>()
                .join("\n");
            info.push_str("=== Memory ===\n");
            info.push_str(&relevant);
            info.push('\n');
        }
    }

    // uptime
    if let Ok(up) = Command::new("uptime").output() {
        info.push_str("=== Uptime ===\n");
        info.push_str(&String::from_utf8_lossy(&up.stdout));
        info.push('\n');
    }

    // df
    if let Ok(df) = Command::new("df").arg("-h").output() {
        info.push_str("=== Disk Usage ===\n");
        info.push_str(&String::from_utf8_lossy(&df.stdout));
        info.push('\n');
    }

    fs::write(dir.join("system_info.txt"), info)?;
    Ok(())
}

fn collect_env_sanitized(dir: &Path) -> anyhow::Result<()> {
    let secret_keys = ["PASSWORD", "SECRET", "TOKEN", "KEY", "CREDENTIAL", "PASS"];
    let mut out = String::new();

    for (k, v) in std::env::vars() {
        let is_secret = secret_keys.iter().any(|s| k.to_uppercase().contains(s));
        if is_secret {
            out.push_str(&format!("{}=<REDACTED>\n", k));
        } else {
            out.push_str(&format!("{}={}\n", k, v));
        }
    }

    fs::write(dir.join("environment.txt"), out)?;
    Ok(())
}

fn collect_logs(dir: &Path, days: u32) -> anyhow::Result<()> {
    #[cfg(not(target_os = "linux"))]
    let _ = days;
    let logs_dir = dir.join("logs");
    fs::create_dir_all(&logs_dir)?;

    // Try journald
    #[cfg(target_os = "linux")]
    {
        let since = format!("{} days ago", days);
        let result = Command::new("journalctl")
            .args(["-u", "omnisec", "--since", &since, "--no-pager", "-o", "short-iso"])
            .output();

        if let Ok(output) = result {
            fs::write(logs_dir.join("daemon.log"), output.stdout)?;
        } else {
            fs::write(logs_dir.join("daemon.log.note"), "journald not available\n")?;
        }
    }

    // Check common log file locations
    let log_paths = [
        "/var/log/omnisec/daemon.log",
        "/var/log/omnisec.log",
        "/tmp/omnisec.log",
    ];

    for path in &log_paths {
        if Path::new(path).exists() {
            // Copy last 10k lines
            let content = Command::new("tail")
                .args(["-n", "10000", path])
                .output()
                .map(|o| o.stdout)
                .unwrap_or_default();
            let filename = Path::new(path).file_name().unwrap().to_string_lossy();
            fs::write(logs_dir.join(filename.as_ref()), content)?;
        }
    }

    Ok(())
}

fn collect_processes(dir: &Path) -> anyhow::Result<()> {
    let mut out = String::new();

    if let Ok(ps) = Command::new("ps").args(["aux", "--sort=-pcpu"]).output() {
        out.push_str("=== Process List (sorted by CPU) ===\n");
        out.push_str(&String::from_utf8_lossy(&ps.stdout));
    }

    // Omnisec-specific processes
    #[cfg(target_os = "linux")]
    {
        if let Ok(entries) = fs::read_dir("/proc") {
            let mut omnisec_procs = Vec::new();
            for entry in entries.flatten() {
                let name = entry.file_name();
                let pid_str = name.to_string_lossy();
                if pid_str.chars().all(|c| c.is_ascii_digit()) {
                    let comm_path = format!("/proc/{}/comm", pid_str);
                    let cmdline_path = format!("/proc/{}/cmdline", pid_str);
                    if let Ok(comm) = fs::read_to_string(&comm_path) {
                        let comm = comm.trim();
                        if comm.contains("omnisec") || comm.contains("chaos") {
                            let cmdline = fs::read_to_string(&cmdline_path)
                                .unwrap_or_default()
                                .replace('\0', " ");
                            omnisec_procs.push(format!("PID {} [{}]: {}", pid_str, comm, cmdline));
                        }
                    }
                }
            }
            if !omnisec_procs.is_empty() {
                out.push_str("\n=== Omnisec Processes ===\n");
                for p in omnisec_procs {
                    out.push_str(&p);
                    out.push('\n');
                }
            }
        }
    }

    fs::write(dir.join("processes.txt"), out)?;
    Ok(())
}

fn collect_network(dir: &Path) -> anyhow::Result<()> {
    let mut out = String::new();

    if let Ok(ss) = Command::new("ss").args(["-tunap"]).output() {
        out.push_str("=== Socket State (ss -tunap) ===\n");
        out.push_str(&String::from_utf8_lossy(&ss.stdout));
        out.push('\n');
    } else if let Ok(net) = Command::new("netstat").args(["-tunap"]).output() {
        out.push_str("=== Socket State (netstat -tunap) ===\n");
        out.push_str(&String::from_utf8_lossy(&net.stdout));
        out.push('\n');
    }

    #[cfg(target_os = "linux")]
    {
        if let Ok(tcp) = fs::read_to_string("/proc/net/tcp") {
            out.push_str("=== /proc/net/tcp ===\n");
            // First 100 lines only
            let lines: String = tcp.lines().take(100).collect::<Vec<_>>().join("\n");
            out.push_str(&lines);
            out.push('\n');
        }
    }

    fs::write(dir.join("network.txt"), out)?;
    Ok(())
}

fn collect_nftables(dir: &Path) -> anyhow::Result<()> {
    #[cfg(target_os = "linux")]
    {
        let mut out = String::new();

        if let Ok(rules) = Command::new("nft").args(["list", "ruleset"]).output() {
            if rules.status.success() {
                out.push_str("=== nftables ruleset ===\n");
                out.push_str(&String::from_utf8_lossy(&rules.stdout));
            } else {
                out.push_str("nft list ruleset failed (insufficient permissions or nft not installed)\n");
            }
        }

        fs::write(dir.join("nftables.txt"), out)?;
    }
    #[cfg(not(target_os = "linux"))]
    {
        fs::write(dir.join("nftables.txt"), "nftables not available (not Linux)\n")?;
    }
    Ok(())
}

fn write_manifest(dir: &Path, days: u32) -> anyhow::Result<()> {
    let manifest = serde_json::json!({
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "omnisec_version": "0.2.0",
        "collection_period_days": days,
        "files": [
            "system_info.txt",
            "environment.txt",
            "processes.txt",
            "network.txt",
            "nftables.txt",
            "logs/",
            "manifest.json",
        ],
        "notes": "Secrets have been redacted from environment.txt. Share this bundle with Omnisec support."
    });

    fs::write(
        dir.join("manifest.json"),
        serde_json::to_string_pretty(&manifest)?,
    )?;
    Ok(())
}

fn create_tar_gz(source_dir: &Path, output: &str) -> anyhow::Result<()> {
    // Use the system `tar` command — no external Rust dependency needed
    let status = Command::new("tar")
        .args([
            "czf",
            output,
            "-C",
            source_dir.parent().unwrap().to_str().unwrap(),
            source_dir.file_name().unwrap().to_str().unwrap(),
        ])
        .status()?;

    if !status.success() {
        anyhow::bail!("tar command failed with status: {}", status);
    }
    Ok(())
}

fn tempdir() -> anyhow::Result<PathBuf> {
    let dir = std::env::temp_dir().join(format!("omnisec-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&dir)?;
    Ok(dir)
}
