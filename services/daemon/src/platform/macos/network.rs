//! macOS network blocking via PF (Packet Filter)
//!
//! Creates and manages an "omnisec" PF anchor. Rules are anchored under
//! /etc/pf.anchors/omnisec and loaded with pfctl.
//!
//! The main /etc/pf.conf must reference the anchor:
//!   anchor "omnisec"
//!   load anchor "omnisec" from "/etc/pf.anchors/omnisec"
//!
//! initialize() installs this reference if missing and enables PF.

use super::super::BlockResult;
use std::collections::HashSet;
use std::fs;
use std::io::Write as IoWrite;
use std::path::Path;

const ANCHOR: &str = "omnisec";
const ANCHOR_FILE: &str = "/etc/pf.anchors/omnisec";
const PF_CONF: &str = "/etc/pf.conf";

/// Ensure PF is enabled and the omnisec anchor is loaded.
/// Idempotent — safe to call on every startup.
pub fn initialize() {
    // Create anchor file if it doesn't exist.
    if !Path::new(ANCHOR_FILE).exists() {
        if let Err(e) = fs::write(ANCHOR_FILE, "# omnisec PF anchor\n") {
            tracing::warn!("pf: could not create {}: {}", ANCHOR_FILE, e);
            return;
        }
    }

    // Inject anchor reference into pf.conf if not already there.
    ensure_pf_conf_anchor();

    // Enable PF.
    let _ = std::process::Command::new("pfctl")
        .args(["-e"])
        .output();

    // Load anchor rules.
    reload_anchor();

    tracing::info!("pf: anchor '{}' initialized from {}", ANCHOR, ANCHOR_FILE);
}

/// Block a destination (domain or IP) by adding a PF block rule.
pub fn block_destination(dest: &str, reason: &str) -> BlockResult {
    let ips = resolve_to_ips(dest);
    if ips.is_empty() {
        tracing::warn!("pf: DNS resolution failed for '{}' — no rule applied", dest);
        return BlockResult {
            success: false,
            method: "pf".to_string(),
            details: format!("DNS resolution failed for {}", dest),
        };
    }

    let mut existing = read_anchor_rules();
    let mut added = 0usize;

    for ip in &ips {
        let rule = format!("block drop out quick proto {{ tcp udp }} from any to {}", ip);
        if !existing.contains(&rule) {
            existing.insert(rule.clone());
            added += 1;
            tracing::info!("pf: blocking {} ({}) — {}", ip, dest, reason);
        }
    }

    if added > 0 {
        if write_anchor_rules(&existing) && reload_anchor() {
            return BlockResult {
                success: true,
                method: "pf".to_string(),
                details: format!(
                    "Added {} drop rules for '{}' ({})",
                    added, dest, reason
                ),
            };
        }
    }

    BlockResult {
        success: added == 0, // already blocked counts as success
        method: "pf".to_string(),
        details: format!("Rules for '{}' already present or reload failed", dest),
    }
}

/// Remove all PF rules whose text contains `dest`.
pub fn unblock_destination(dest: &str) -> bool {
    let before = read_anchor_rules();
    let after: HashSet<String> = before
        .iter()
        .filter(|r| !r.contains(dest))
        .cloned()
        .collect();

    let removed = before.len() - after.len();
    if removed == 0 {
        return false;
    }

    if write_anchor_rules(&after) && reload_anchor() {
        tracing::info!("pf: removed {} rule(s) for '{}'", removed, dest);
        true
    } else {
        false
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn read_anchor_rules() -> HashSet<String> {
    match fs::read_to_string(ANCHOR_FILE) {
        Ok(content) => content
            .lines()
            .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
            .map(|l| l.to_string())
            .collect(),
        Err(_) => HashSet::new(),
    }
}

fn write_anchor_rules(rules: &HashSet<String>) -> bool {
    let mut content = String::from("# omnisec PF anchor — managed by omnisec-daemon\n");
    for rule in rules {
        content.push_str(rule);
        content.push('\n');
    }
    match fs::write(ANCHOR_FILE, content) {
        Ok(_) => true,
        Err(e) => {
            tracing::warn!("pf: failed to write {}: {}", ANCHOR_FILE, e);
            false
        }
    }
}

fn reload_anchor() -> bool {
    std::process::Command::new("pfctl")
        .args(["-a", ANCHOR, "-f", ANCHOR_FILE])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn ensure_pf_conf_anchor() {
    let content = match fs::read_to_string(PF_CONF) {
        Ok(c) => c,
        Err(_) => return,
    };

    if content.contains(ANCHOR) {
        return;
    }

    // Append anchor reference lines.
    let addition = format!(
        "\n# omnisec anchor (added by omnisec-daemon)\nanchor \"{}\"\nload anchor \"{}\" from \"{}\"\n",
        ANCHOR, ANCHOR, ANCHOR_FILE
    );

    if let Ok(mut f) = fs::OpenOptions::new().append(true).open(PF_CONF) {
        let _ = f.write_all(addition.as_bytes());
    }
}

fn resolve_to_ips(dest: &str) -> Vec<String> {
    use std::net::ToSocketAddrs;
    let addr = format!("{}:80", dest);
    match addr.to_socket_addrs() {
        Ok(addrs) => {
            let unique: HashSet<String> = addrs.map(|a| a.ip().to_string()).collect();
            let ips: Vec<String> = unique.into_iter().collect();
            if !ips.is_empty() {
                tracing::debug!("DNS resolved {} → {:?}", dest, ips);
            }
            ips
        }
        Err(e) => {
            tracing::warn!("DNS resolution failed for {}: {}", dest, e);
            Vec::new()
        }
    }
}
