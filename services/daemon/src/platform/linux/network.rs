//! Linux network blocking via nftables
//!
//! Creates an "omnisec" inet table with an "omnisec-block" output chain.
//! Resolves domain names to IPs before inserting rules (nftables cannot
//! match by hostname).

use super::super::BlockResult;

const TABLE: &str = "omnisec";
const CHAIN: &str = "omnisec-block";

/// Create the nftables table and output chain used by OmniSec.
/// Idempotent — safe to call on every startup.
pub fn initialize() {
    let _ = std::process::Command::new("nft")
        .args(["add", "table", "inet", TABLE])
        .output();

    let chain_def = format!(
        "{{ type filter hook output priority 0; policy accept; }}"
    );
    let _ = std::process::Command::new("nft")
        .args([
            "add", "chain", "inet", TABLE, CHAIN,
            &chain_def,
        ])
        .output();

    tracing::info!("nftables: table 'inet {}' chain '{}' initialized", TABLE, CHAIN);
}

/// Block a destination (domain or IP) via nftables drop rules.
pub fn block_destination(dest: &str, reason: &str) -> BlockResult {
    let ips = resolve_to_ips(dest);
    if ips.is_empty() {
        tracing::warn!("nftables: DNS resolution failed for '{}' — no rule applied", dest);
        return BlockResult {
            success: false,
            method: "nftables".to_string(),
            details: format!("DNS resolution failed for {}", dest),
        };
    }

    let mut applied = 0usize;
    for ip in &ips {
        let ok = std::process::Command::new("nft")
            .args([
                "add", "rule", "inet", TABLE, CHAIN,
                "ip", "daddr", ip, "drop",
            ])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);

        if ok {
            applied += 1;
            tracing::info!("nftables: blocked {} ({}) — {}", ip, dest, reason);
        } else {
            tracing::warn!("nftables: failed to block {}", ip);
        }
    }

    BlockResult {
        success: applied > 0,
        method: "nftables".to_string(),
        details: format!(
            "Applied {} of {} drop rules for '{}' — {}",
            applied,
            ips.len(),
            dest,
            reason,
        ),
    }
}

/// Remove all nftables rules whose comment or destination matches `dest`.
pub fn unblock_destination(dest: &str) -> bool {
    let output = match std::process::Command::new("nft")
        .args(["-a", "list", "chain", "inet", TABLE, CHAIN])
        .output()
    {
        Ok(o) => o,
        Err(_) => return false,
    };

    let text = String::from_utf8_lossy(&output.stdout);
    let mut removed = 0usize;

    for line in text.lines() {
        if !line.contains(dest) {
            continue;
        }
        // Extract handle number from "... # handle N"
        if let Some(handle) = line
            .split("handle")
            .nth(1)
            .and_then(|s| s.trim().split_whitespace().next())
        {
            let ok = std::process::Command::new("nft")
                .args([
                    "delete", "rule", "inet", TABLE, CHAIN,
                    "handle", handle,
                ])
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false);
            if ok {
                removed += 1;
                tracing::info!("nftables: unblocked handle {} ({})", handle, dest);
            }
        }
    }

    removed > 0
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn resolve_to_ips(dest: &str) -> Vec<String> {
    use std::net::ToSocketAddrs;
    let addr = format!("{}:80", dest);
    match addr.to_socket_addrs() {
        Ok(addrs) => {
            let unique: std::collections::HashSet<String> =
                addrs.map(|a| a.ip().to_string()).collect();
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
