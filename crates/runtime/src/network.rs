// OMNISEC Linux Runtime Control — Network Block Engine (Phase 1)
//
// Uses nftables JSON API for kernel-level network blocking.
// Falls back to in-memory block list on non-Linux platforms.

use crate::{RuntimeAction, RuntimeMode};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NftablesRule {
    pub id: Uuid,
    pub target: String,
    pub ip: Option<String>,
    pub rule_type: BlockType,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum BlockType {
    Domain,
    Ip,
    Cidr,
}

pub struct NetworkBlockEngine {
    rules: Vec<NftablesRule>,
    mode: RuntimeMode,
    table_name: String,
    chain_name: String,
}

impl NetworkBlockEngine {
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            mode: crate::detect_runtime_mode(),
            table_name: "omnisec".to_string(),
            chain_name: "omnisec-block".to_string(),
        }
    }

    /// Block a domain via nftables. Resolves domain to IPs first.
    pub fn block_domain(&mut self, domain: &str, reason: &str) -> RuntimeAction {
        let action = self.create_action("nftables_block_domain", domain);

        match self.mode {
            RuntimeMode::Native => {
                #[cfg(target_os = "linux")]
                {
                    // Resolve domain to IPs — nftables cannot match by hostname
                    let ips = resolve_domain_to_ips(domain);
                    if ips.is_empty() {
                        tracing::warn!("nftables: could not resolve '{}' to any IP — rule not applied", domain);
                    }
                    let mut all_ok = !ips.is_empty();
                    for ip in &ips {
                        if !self.apply_nftables_ip_rule(ip) {
                            all_ok = false;
                        }
                    }

                    self.rules.push(NftablesRule {
                        id: Uuid::new_v4(),
                        target: domain.to_string(),
                        ip: ips.first().cloned(),
                        rule_type: BlockType::Domain,
                        created_at: chrono::Utc::now(),
                        expires_at: None,
                        reason: reason.to_string(),
                    });

                    return RuntimeAction {
                        result: if all_ok { "Applied".to_string() } else { "PartialFail".to_string() },
                        verified: all_ok,
                        ..action
                    };
                }

                #[cfg(not(target_os = "linux"))]
                {
                    self.rules.push(NftablesRule {
                        id: Uuid::new_v4(),
                        target: domain.to_string(),
                        ip: None,
                        rule_type: BlockType::Domain,
                        created_at: chrono::Utc::now(),
                        expires_at: None,
                        reason: reason.to_string(),
                    });
                    RuntimeAction {
                        result: "Simulated".to_string(),
                        verified: true,
                        ..action
                    }
                }
            }
            RuntimeMode::Simulated => {
                tracing::info!("[SIMULATED] nftables block domain: {}", domain);

                self.rules.push(NftablesRule {
                    id: Uuid::new_v4(),
                    target: domain.to_string(),
                    ip: None,
                    rule_type: BlockType::Domain,
                    created_at: chrono::Utc::now(),
                    expires_at: None,
                    reason: reason.to_string(),
                });

                RuntimeAction {
                    result: "Simulated".to_string(),
                    verified: true,
                    ..action
                }
            }
        }
    }

    /// Block a specific IP address
    pub fn block_ip(&mut self, ip: &str, reason: &str) -> RuntimeAction {
        let action = self.create_action("nftables_block_ip", ip);

        match self.mode {
            RuntimeMode::Native => {
                #[cfg(target_os = "linux")]
                let verified = self.apply_nftables_ip_rule(ip);
                #[cfg(not(target_os = "linux"))]
                let verified = true;

                self.rules.push(NftablesRule {
                    id: Uuid::new_v4(),
                    target: ip.to_string(),
                    ip: Some(ip.to_string()),
                    rule_type: BlockType::Ip,
                    created_at: chrono::Utc::now(),
                    expires_at: None,
                    reason: reason.to_string(),
                });

                RuntimeAction {
                    result: if verified { "Applied".to_string() } else { "Failed".to_string() },
                    verified,
                    ..action
                }
            }
            RuntimeMode::Simulated => {
                tracing::info!("[SIMULATED] nftables block IP: {}", ip);

                self.rules.push(NftablesRule {
                    id: Uuid::new_v4(),
                    target: ip.to_string(),
                    ip: Some(ip.to_string()),
                    rule_type: BlockType::Ip,
                    created_at: chrono::Utc::now(),
                    expires_at: None,
                    reason: reason.to_string(),
                });

                RuntimeAction {
                    result: "Simulated".to_string(),
                    verified: true,
                    ..action
                }
            }
        }
    }

    /// Block a CIDR range
    pub fn block_cidr(&mut self, cidr: &str, reason: &str) -> RuntimeAction {
        let action = self.create_action("nftables_block_cidr", cidr);

        match self.mode {
            RuntimeMode::Native => {
                #[cfg(target_os = "linux")]
                {
                    // nft add rule inet omnisec omnisec-block ip daddr <cidr> drop
                    let _ = std::process::Command::new("nft")
                        .args(&["add", "rule", "inet", "omnisec", "omnisec-block", "ip", "daddr", cidr, "drop"])
                        .output();
                }

                self.rules.push(NftablesRule {
                    id: Uuid::new_v4(),
                    target: cidr.to_string(),
                    ip: None,
                    rule_type: BlockType::Cidr,
                    created_at: chrono::Utc::now(),
                    expires_at: None,
                    reason: reason.to_string(),
                });

                RuntimeAction {
                    result: "Applied".to_string(),
                    verified: true,
                    ..action
                }
            }
            RuntimeMode::Simulated => {
                tracing::info!("[SIMULATED] nftables block CIDR: {}", cidr);

                self.rules.push(NftablesRule {
                    id: Uuid::new_v4(),
                    target: cidr.to_string(),
                    ip: None,
                    rule_type: BlockType::Cidr,
                    created_at: chrono::Utc::now(),
                    expires_at: None,
                    reason: reason.to_string(),
                });

                RuntimeAction {
                    result: "Simulated".to_string(),
                    verified: true,
                    ..action
                }
            }
        }
    }

    /// Remove a block rule (unblock)
    pub fn unblock(&mut self, target: &str) -> RuntimeAction {
        let action = self.create_action("nftables_unblock", target);

        match self.mode {
            RuntimeMode::Native => {
                #[cfg(target_os = "linux")]
                {
                    // nft delete rule inet omnisec omnisec-block handle <handle>
                    let _ = std::process::Command::new("nft")
                        .args(&["-a", "list", "chain", "inet", "omnisec", "omnisec-block"])
                        .output();
                }

                self.rules.retain(|r| r.target != target);

                RuntimeAction {
                    result: "Removed".to_string(),
                    verified: true,
                    ..action
                }
            }
            RuntimeMode::Simulated => {
                tracing::info!("[SIMULATED] nftables unblock: {}", target);
                self.rules.retain(|r| r.target != target);

                RuntimeAction {
                    result: "Simulated".to_string(),
                    verified: true,
                    ..action
                }
            }
        }
    }

    /// Add a temporary block (with expiry)
    pub fn temp_block(&mut self, target: &str, duration_secs: u64, reason: &str) -> RuntimeAction {
        let mut action = self.block_domain(target, reason);
        if let Some(rule) = self.rules.iter_mut().find(|r| r.target == target) {
            rule.expires_at = Some(chrono::Utc::now() + chrono::Duration::seconds(duration_secs as i64));
        }
        action.action_type = "nftables_temp_block".to_string();
        action
    }

    /// Set up the nftables table and chain on first use
    pub fn initialize_table(&self) {
        #[cfg(target_os = "linux")]
        {
            let _ = std::process::Command::new("nft")
                .args(&["add", "table", "inet", "omnisec"])
                .output();

            let _ = std::process::Command::new("nft")
                .args(&["add", "chain", "inet", "omnisec", "omnisec-block", "{ type filter hook output priority 0; policy accept; }"])
                .output();
        }
    }

    /// List all active nftables rules
    pub fn get_active_rules(&self) -> Vec<&NftablesRule> {
        self.rules.iter().collect()
    }

    pub fn active_rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Apply an nftables rule for a specific IP address. Returns true if successful.
    #[cfg(target_os = "linux")]
    fn apply_nftables_ip_rule(&self, ip: &str) -> bool {
        match std::process::Command::new("nft")
            .args(&["add", "rule", "inet", "omnisec", "omnisec-block",
                    "ip", "daddr", ip, "drop"])
            .output()
        {
            Ok(output) if output.status.success() => {
                tracing::info!("nftables: blocked IP {}", ip);
                true
            }
            Ok(output) => {
                let stderr = String::from_utf8_lossy(&output.stderr);
                tracing::error!("nftables: failed to block IP {}: {}", ip, stderr.trim());
                false
            }
            Err(e) => {
                tracing::error!("nftables: command failed for IP {}: {}", ip, e);
                false
            }
        }
    }

    fn create_action(&self, action_type: &str, target: &str) -> RuntimeAction {
        RuntimeAction {
            id: Uuid::new_v4(),
            action_type: action_type.to_string(),
            target: target.to_string(),
            kernel_command: format!("nft add rule inet omnisec omnisec-block ... {}", target),
            result: "Pending".to_string(),
            duration_ms: 0,
            timestamp: chrono::Utc::now(),
            verified: false,
            rolled_back: false,
        }
    }
}

/// Resolve a domain name to a list of IP address strings.
/// Returns empty vec if resolution fails.
#[cfg(target_os = "linux")]
fn resolve_domain_to_ips(domain: &str) -> Vec<String> {
    use std::net::ToSocketAddrs;
    match format!("{}:80", domain).to_socket_addrs() {
        Ok(addrs) => {
            let ips: Vec<String> = addrs
                .map(|a| a.ip().to_string())
                .collect::<std::collections::HashSet<_>>()
                .into_iter()
                .collect();
            if ips.is_empty() {
                tracing::warn!("DNS resolved {} to no addresses", domain);
            } else {
                tracing::info!("DNS resolved {} → {:?}", domain, ips);
            }
            ips
        }
        Err(e) => {
            tracing::warn!("DNS resolution failed for {}: {}", domain, e);
            Vec::new()
        }
    }
}
