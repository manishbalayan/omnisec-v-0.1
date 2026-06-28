//! Linux process monitoring via /proc filesystem
//!
//! Reads /proc/{pid}/comm, /proc/{pid}/stat, and /proc/{pid}/cmdline
//! to enumerate and inspect running processes.

use super::super::ProcessEntry;
use std::fs;

/// Returns the host `/proc` root. OmniSec runs natively on the host.
pub fn proc_root() -> &'static str {
    "/proc"
}

/// Enumerate all processes by scanning /proc.
pub fn list_processes() -> Vec<ProcessEntry> {
    let root = proc_root();
    let mut out = Vec::new();

    let dir = match fs::read_dir(root) {
        Ok(d) => d,
        Err(e) => {
            tracing::warn!("Cannot read {}: {}", root, e);
            return out;
        }
    };

    for entry in dir.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if let Ok(pid) = name.parse::<u32>() {
            if let Some(p) = read_proc_entry(pid) {
                out.push(p);
            }
        }
    }
    out
}

fn read_proc_entry(pid: u32) -> Option<ProcessEntry> {
    let root = proc_root();
    let comm = fs::read_to_string(format!("{}/{}/comm", root, pid)).ok()?;
    let stat = fs::read_to_string(format!("{}/{}/stat", root, pid)).ok()?;
    let cmdline = read_cmdline(pid).unwrap_or_default();

    // /proc/pid/stat field 4 (0-indexed 3) is ppid
    let fields: Vec<&str> = stat.split_whitespace().collect();
    let ppid: u32 = fields.get(3).and_then(|s| s.parse().ok()).unwrap_or(0);

    Some(ProcessEntry {
        pid,
        ppid,
        comm: comm.trim().to_string(),
        cmdline,
    })
}

/// Read /proc/{pid}/cmdline and return as a space-joined command string.
/// argv is NUL-separated in the file.
pub fn read_cmdline(pid: u32) -> Option<String> {
    let root = proc_root();
    let content = fs::read(format!("{}/{}/cmdline", root, pid)).ok()?;
    let args: Vec<String> = content
        .split(|&b| b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).to_string())
        .collect();
    if args.is_empty() {
        None
    } else {
        Some(args.join(" "))
    }
}
