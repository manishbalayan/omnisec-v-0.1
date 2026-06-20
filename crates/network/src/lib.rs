use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::net::IpAddr;

// ---------------------------------------------------------------------------
// Data structures
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionInfo {
    pub pid: u32,
    pub process_name: String,
    pub local_ip: IpAddr,
    pub local_port: u16,
    pub remote_ip: IpAddr,
    pub remote_port: u16,
    pub protocol: Protocol,
    pub state: ConnectionState,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Protocol {
    Tcp,
    Udp,
    Raw,
    Unix,
    Unknown(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ConnectionState {
    Established,
    Listen,
    CloseWait,
    TimeWait,
    SynSent,
    SynRecv,
    Unknown(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionKey {
    pub local_ip: IpAddr,
    pub local_port: u16,
    pub remote_ip: IpAddr,
    pub remote_port: u16,
    pub protocol: Protocol,
}

impl Hash for ConnectionKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.local_ip.hash(state);
        self.local_port.hash(state);
        self.remote_ip.hash(state);
        self.remote_port.hash(state);
        format!("{:?}", self.protocol).hash(state);
    }
}

impl PartialEq for ConnectionKey {
    fn eq(&self, other: &Self) -> bool {
        self.local_ip == other.local_ip
            && self.local_port == other.local_port
            && self.remote_ip == other.remote_ip
            && self.remote_port == other.remote_port
            && self.protocol == other.protocol
    }
}

impl Eq for ConnectionKey {}

// ---------------------------------------------------------------------------
// Traffic rolling windows
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficSnapshot {
    pub timestamp: DateTime<Utc>,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub connection_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RollingTrafficWindow {
    pub hour_samples: Vec<TrafficSnapshot>,
    pub day_samples: Vec<TrafficSnapshot>,
    pub week_samples: Vec<TrafficSnapshot>,
}

impl RollingTrafficWindow {
    pub fn new() -> Self {
        Self {
            hour_samples: Vec::with_capacity(60),    // 1 per min for 60 min
            day_samples: Vec::with_capacity(1440),    // 1 per min for 1440 min
            week_samples: Vec::with_capacity(10080),   // 1 per min for 10080 min
        }
    }

    pub fn add_sample(&mut self, sample: TrafficSnapshot) {
        self.hour_samples.push(sample.clone());
        self.day_samples.push(sample.clone());
        self.week_samples.push(sample.clone());

        let now = Utc::now();
        self.hour_samples.retain(|s| {
            (now - s.timestamp).num_minutes() < 60
        });
        self.day_samples.retain(|s| {
            (now - s.timestamp).num_hours() < 24
        });
        self.week_samples.retain(|s| {
            (now - s.timestamp).num_days() < 7
        });
    }

    pub fn avg_bytes_in_per_min(&self) -> f64 {
        if self.hour_samples.is_empty() {
            return 0.0;
        }
        let total: u64 = self.hour_samples.iter().map(|s| s.bytes_in).sum();
        total as f64 / self.hour_samples.len() as f64
    }

    pub fn avg_bytes_out_per_min(&self) -> f64 {
        if self.hour_samples.is_empty() {
            return 0.0;
        }
        let total: u64 = self.hour_samples.iter().map(|s| s.bytes_out).sum();
        total as f64 / self.hour_samples.len() as f64
    }
}

impl Default for RollingTrafficWindow {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Network tracker
// ---------------------------------------------------------------------------

pub struct NetworkTracker {
    /// Active connections keyed by (pid, ConnectionKey)
    connections: HashMap<(u32, ConnectionKey), ConnectionInfo>,
    /// Traffic rolling windows keyed by pid
    traffic_windows: HashMap<u32, RollingTrafficWindow>,
    /// Seen (domain, ip, port, protocol) tuples per pid for destination profiling
    seen_destinations: HashMap<u32, HashSet<(String, u16, String)>>,
    /// Process name cache
    process_names: HashMap<u32, String>,
}

impl NetworkTracker {
    pub fn new() -> Self {
        Self {
            connections: HashMap::new(),
            traffic_windows: HashMap::new(),
            seen_destinations: HashMap::new(),
            process_names: HashMap::new(),
        }
    }

    /// Register a connection from packet capture or /proc/net parsing.
    /// Returns true if this is a new connection.
    pub fn register_connection(
        &mut self,
        pid: u32,
        process_name: String,
        local_ip: IpAddr,
        local_port: u16,
        remote_ip: IpAddr,
        remote_port: u16,
        protocol: Protocol,
        state: ConnectionState,
        bytes_in: u64,
        bytes_out: u64,
    ) -> bool {
        self.process_names.insert(pid, process_name.clone());

        let key = ConnectionKey {
            local_ip,
            local_port,
            remote_ip,
            remote_port,
            protocol: protocol.clone(),
        };

        let now = Utc::now();
        let existing_entry = self.connections.get(&(pid, key.clone()));
        let is_new = existing_entry.is_none();
        let first_seen = existing_entry.map(|e| e.first_seen).unwrap_or(now);
        let proto_str = protocol_str(&protocol);

        self.connections.insert(
            (pid, key),
            ConnectionInfo {
                pid,
                process_name,
                local_ip,
                local_port,
                remote_ip,
                remote_port,
                protocol,
                state,
                bytes_in,
                bytes_out,
                first_seen,
                last_seen: now,
            },
        );

        // Track destination for profiling
        let dest_key = (remote_ip.to_string(), remote_port, proto_str);
        self.seen_destinations
            .entry(pid)
            .or_default()
            .insert(dest_key);

        // Record traffic sample
        let traffic = TrafficSnapshot {
            timestamp: now,
            bytes_in,
            bytes_out,
            connection_count: self.connections.len(),
        };
        self.traffic_windows
            .entry(pid)
            .or_insert_with(RollingTrafficWindow::new)
            .add_sample(traffic);

        is_new
    }

    /// Remove a closed connection.
    pub fn remove_connection(
        &mut self,
        pid: u32,
        remote_ip: IpAddr,
        remote_port: u16,
    ) {
        let keys: Vec<(u32, ConnectionKey)> = self
            .connections
            .keys()
            .filter(|(p, k)| *p == pid && k.remote_ip == remote_ip && k.remote_port == remote_port)
            .cloned()
            .collect();
        for key in keys {
            self.connections.remove(&key);
        }
    }

    /// Get all active connections for a process.
    pub fn get_connections_for_pid(&self, pid: u32) -> Vec<&ConnectionInfo> {
        self.connections
            .iter()
            .filter(|((p, _), _)| *p == pid)
            .map(|(_, c)| c)
            .collect()
    }

    /// Get traffic stats for a process.
    pub fn get_traffic_stats(&self, pid: u32) -> TrafficStats {
        let connections = self.get_connections_for_pid(pid);
        let total_in: u64 = connections.iter().map(|c| c.bytes_in).sum();
        let total_out: u64 = connections.iter().map(|c| c.bytes_out).sum();
        let windows = self.traffic_windows.get(&pid);

        TrafficStats {
            pid,
            active_connections: connections.len() as u32,
            total_bytes_in: total_in,
            total_bytes_out: total_out,
            hour_avg_in: windows.map(|w| w.avg_bytes_in_per_min()).unwrap_or(0.0),
            hour_avg_out: windows.map(|w| w.avg_bytes_out_per_min()).unwrap_or(0.0),
            unique_destinations: self
                .seen_destinations
                .get(&pid)
                .map(|s| s.len() as u32)
                .unwrap_or(0),
        }
    }

    /// Get all destinations seen for a process.
    pub fn get_destinations(&self, pid: u32) -> Vec<(String, u16, String)> {
        self.seen_destinations
            .get(&pid)
            .map(|s| s.iter().cloned().collect())
            .unwrap_or_default()
        }

    /// Check if a destination is new for this process.
    pub fn is_new_destination(&self, pid: u32, ip: &str, port: u16, protocol: &str) -> bool {
        self.seen_destinations
            .get(&pid)
            .map(|s| !s.contains(&(ip.to_string(), port, protocol.to_string())))
            .unwrap_or(true)
    }

    /// Get the total number of tracked connections.
    pub fn connection_count(&self) -> usize {
        self.connections.len()
    }

    /// Collect live connections from the OS and register them.
    /// On Linux: reads /proc/net/tcp and maps inodes → PIDs via /proc/[pid]/fd/.
    /// On macOS: runs `lsof -i -n -P`.
    /// On other platforms: no-op.
    pub fn collect_connections(&mut self) {
        #[cfg(target_os = "linux")]
        self.collect_connections_linux();

        #[cfg(target_os = "macos")]
        self.collect_connections_macos();
    }

    #[cfg(target_os = "linux")]
    fn collect_connections_linux(&mut self) {
        let inode_map = build_inode_pid_map();
        let proc_conns = parse_proc_net_tcp();

        for conn in proc_conns {
            if conn.inode == 0 { continue; }
            let Some(&pid) = inode_map.get(&conn.inode) else { continue; };

            let local_ip: IpAddr = match conn.local_ip.parse() {
                Ok(ip) => ip,
                Err(_) => continue,
            };
            let remote_ip: IpAddr = match conn.remote_ip.parse() {
                Ok(ip) => ip,
                Err(_) => continue,
            };

            // Skip connections to 0.0.0.0 (listen sockets) or local loopback
            if conn.remote_ip == "0.0.0.0" { continue; }

            let process_name = self.process_names.get(&pid)
                .cloned()
                .unwrap_or_else(|| read_proc_comm(pid));

            self.register_connection(
                pid,
                process_name,
                local_ip,
                conn.local_port,
                remote_ip,
                conn.remote_port,
                Protocol::Tcp,
                conn.state,
                0, // /proc/net/tcp has no per-connection byte counts
                0,
            );
        }

        self.prune_stale_connections(60);
    }

    #[cfg(target_os = "macos")]
    fn collect_connections_macos(&mut self) {
        // lsof -i -n -P: list internet connections without DNS resolution or port name lookup
        let output = match std::process::Command::new("lsof")
            .args(["-i", "-n", "-P"])
            .output()
        {
            Ok(o) if o.status.success() => o,
            Ok(o) => {
                tracing::warn!("lsof failed: {}", String::from_utf8_lossy(&o.stderr).trim());
                return;
            }
            Err(e) => {
                tracing::warn!("lsof not available: {}", e);
                return;
            }
        };

        let stdout = String::from_utf8_lossy(&output.stdout);
        // lsof columns: COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
        // We want lines with TCP/UDP and an ESTABLISHED state
        for line in stdout.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 10 { continue; }

            let pid: u32 = match fields[1].parse() { Ok(p) => p, Err(_) => continue };
            let proto = fields[7]; // e.g. TCP, UDP
            if proto != "TCP" && proto != "UDP" { continue; }

            let name = fields[8]; // e.g. 127.0.0.1:8080->93.184.216.34:443
            let state = fields.get(9).copied().unwrap_or("");

            // Parse "local->remote" or "local" (listen)
            let Some((local_str, remote_str)) = name.split_once("->") else { continue };

            let parse_addr = |s: &str| -> Option<(IpAddr, u16)> {
                // Handle "[::1]:port" and "1.2.3.4:port"
                let (ip_s, port_s) = if s.starts_with('[') {
                    let end = s.find(']')?;
                    (&s[1..end], &s[end + 2..])
                } else {
                    s.rsplit_once(':')?
                };
                Some((ip_s.parse().ok()?, port_s.parse().ok()?))
            };

            let Some((local_ip, local_port)) = parse_addr(local_str) else { continue };
            let Some((remote_ip, remote_port)) = parse_addr(remote_str) else { continue };

            let conn_state = if state == "ESTABLISHED" {
                ConnectionState::Established
            } else {
                ConnectionState::Unknown(state.to_string())
            };

            let protocol = if proto == "TCP" { Protocol::Tcp } else { Protocol::Udp };
            let process_name = self.process_names.get(&pid)
                .cloned()
                .unwrap_or_else(|| fields[0].to_string());

            self.register_connection(
                pid, process_name,
                local_ip, local_port,
                remote_ip, remote_port,
                protocol, conn_state,
                0, 0,
            );
        }

        self.prune_stale_connections(60);
    }

    /// Clear stale connections (no update in N seconds).
    pub fn prune_stale_connections(&mut self, max_age_secs: i64) {
        let now = Utc::now();
        self.connections.retain(|_, c| {
            (now - c.last_seen).num_seconds() < max_age_secs
        });
    }

    /// Collect traffic snapshot across all PIDs for this cycle.
    pub fn collect_traffic_snapshot(&self) -> Vec<TrafficUpdate> {
        let mut updates = Vec::new();
        let mut seen_pids: HashSet<u32> = HashSet::new();
        for ((pid, _), _) in &self.connections {
            if seen_pids.insert(*pid) {
                let stats = self.get_traffic_stats(*pid);
                updates.push(TrafficUpdate {
                    pid: stats.pid,
                    process_name: self
                        .process_names
                        .get(&stats.pid)
                        .cloned()
                        .unwrap_or_default(),
                    total_bytes_in: stats.total_bytes_in,
                    total_bytes_out: stats.total_bytes_out,
                    connection_count: stats.active_connections,
                });
            }
        }
        updates
    }
}

impl Default for NetworkTracker {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Supporting types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficStats {
    pub pid: u32,
    pub active_connections: u32,
    pub total_bytes_in: u64,
    pub total_bytes_out: u64,
    pub hour_avg_in: f64,
    pub hour_avg_out: f64,
    pub unique_destinations: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficUpdate {
    pub pid: u32,
    pub process_name: String,
    pub total_bytes_in: u64,
    pub total_bytes_out: u64,
    pub connection_count: u32,
}

// ---------------------------------------------------------------------------
// Linux helpers
// ---------------------------------------------------------------------------

/// Build a map from socket inode → PID by scanning /proc/[pid]/fd/.
#[cfg(target_os = "linux")]
pub fn build_inode_pid_map() -> std::collections::HashMap<u64, u32> {
    let mut map = std::collections::HashMap::new();
    let proc_dir = match std::fs::read_dir("/proc") {
        Ok(d) => d,
        Err(_) => return map,
    };
    for entry in proc_dir.flatten() {
        let pid: u32 = match entry.file_name().to_str().and_then(|s| s.parse().ok()) {
            Some(p) => p,
            None => continue,
        };
        let fd_path = format!("/proc/{}/fd", pid);
        let fd_dir = match std::fs::read_dir(&fd_path) {
            Ok(d) => d,
            Err(_) => continue,
        };
        for fd_entry in fd_dir.flatten() {
            if let Ok(link) = std::fs::read_link(fd_entry.path()) {
                let s = link.to_string_lossy();
                // Socket fds look like "socket:[12345]"
                if let Some(inner) = s.strip_prefix("socket:[").and_then(|s| s.strip_suffix(']')) {
                    if let Ok(inode) = inner.parse::<u64>() {
                        map.insert(inode, pid);
                    }
                }
            }
        }
    }
    map
}

/// Read /proc/[pid]/comm for the process name.
#[cfg(target_os = "linux")]
fn read_proc_comm(pid: u32) -> String {
    std::fs::read_to_string(format!("/proc/{}/comm", pid))
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| format!("pid-{}", pid))
}

#[cfg(not(target_os = "linux"))]
pub fn build_inode_pid_map() -> std::collections::HashMap<u64, u32> {
    std::collections::HashMap::new()
}

// ---------------------------------------------------------------------------
// Linux /proc/net parsing helpers
// ---------------------------------------------------------------------------

/// Parse /proc/net/tcp to extract TCP connection info for a given PID.
/// Returns list of (remote_ip, remote_port, local_port, state, bytes_in, bytes_out).
///
/// Note: Full per-pid connection tracking requires netlink or auditd.
/// This function demonstrates the procfs approach for basic tracking.
#[cfg(target_os = "linux")]
pub fn parse_proc_net_tcp() -> Vec<ProcConnection> {
    let mut connections = Vec::new();
    let content = match std::fs::read_to_string("/proc/net/tcp") {
        Ok(c) => c,
        Err(_) => return connections,
    };

    for line in content.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 12 {
            continue;
        }

        // Parse local and remote addresses (format: 0100007F:0035)
        let local = fields[1];
        let remote = fields[2];
        let state_code = fields[3];

        let (local_ip, local_port) = parse_socket_addr(local);
        let (remote_ip, remote_port) = parse_socket_addr(remote);
        let state = parse_tcp_state(state_code);

        // Get the inode to map to PID
        let inode: u64 = fields.get(9).and_then(|s| s.parse().ok()).unwrap_or(0);

        // Note: mapping inode -> PID requires scanning /proc/[pid]/fd
        // This is a simplified version; a full implementation would need per-pid fd scanning

        connections.push(ProcConnection {
            local_ip,
            local_port,
            remote_ip,
            remote_port,
            state,
            inode,
            rx_bytes: 0, // /proc/net/tcp doesn't provide byte counts per connection
            tx_bytes: 0,  // Need /proc/[pid]/net/dev or netlink for this
        });
    }

    connections
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone)]
pub struct ProcConnection {
    pub local_ip: String,
    pub local_port: u16,
    pub remote_ip: String,
    pub remote_port: u16,
    pub state: ConnectionState,
    pub inode: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

// These helpers are public and used both in the Linux parser and in tests,
// so they must be available on all platforms.

/// Parse a hex-encoded socket address (e.g., "0100007F:0035" -> 127.0.0.1:53).
pub fn parse_socket_addr(addr: &str) -> (String, u16) {
    let parts: Vec<&str> = addr.split(':').collect();
    if parts.len() != 2 {
        return ("0.0.0.0".to_string(), 0);
    }

    let ip_hex = parts[0];
    let port_hex = parts[1];

    // Parse little-endian hex IP (e.g., 0100007F -> 7F000001 -> 127.0.0.1)
    let ip_bytes: Vec<u8> = (0..4)
        .map(|i| {
            let start = i * 2;
            u8::from_str_radix(&ip_hex[start..start + 2], 16).unwrap_or(0)
        })
        .collect();

    let ip = format!("{}.{}.{}.{}", ip_bytes[3], ip_bytes[2], ip_bytes[1], ip_bytes[0]);
    let port = u16::from_str_radix(port_hex, 16).unwrap_or(0);

    (ip, port)
}

/// Parse TCP state code to enum.
pub fn parse_tcp_state(code: &str) -> ConnectionState {
    match code {
        "01" => ConnectionState::Established,
        "02" => ConnectionState::SynSent,
        "03" => ConnectionState::SynRecv,
        "04" => ConnectionState::TimeWait,
        "05" => ConnectionState::CloseWait,
        "0A" => ConnectionState::Listen,
        _ => ConnectionState::Unknown(code.to_string()),
    }
}

/// Convert protocol to string.
fn protocol_str(p: &Protocol) -> String {
    match p {
        Protocol::Tcp => "tcp".to_string(),
        Protocol::Udp => "udp".to_string(),
        Protocol::Raw => "raw".to_string(),
        Protocol::Unix => "unix".to_string(),
        Protocol::Unknown(s) => s.clone(),
    }
}

// ---------------------------------------------------------------------------
// Non-Linux stub
// ---------------------------------------------------------------------------

#[cfg(not(target_os = "linux"))]
pub fn parse_proc_net_tcp() -> Vec<ProcConnection> {
    Vec::new()
}

#[cfg(not(target_os = "linux"))]
#[derive(Debug, Clone)]
pub struct ProcConnection {
    pub local_ip: String,
    pub local_port: u16,
    pub remote_ip: String,
    pub remote_port: u16,
    pub state: ConnectionState,
    pub inode: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_register_and_track_connection() {
        let mut tracker = NetworkTracker::new();

        let is_new = tracker.register_connection(
            1234,
            "test-agent".to_string(),
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            9000,
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            443,
            Protocol::Tcp,
            ConnectionState::Established,
            1000,
            500,
        );

        assert!(is_new, "First registration should be new");
        assert_eq!(tracker.connection_count(), 1);

        let connections = tracker.get_connections_for_pid(1234);
        assert_eq!(connections.len(), 1);
        assert_eq!(connections[0].bytes_in, 1000);
        assert_eq!(connections[0].bytes_out, 500);

        let stats = tracker.get_traffic_stats(1234);
        assert_eq!(stats.active_connections, 1);
        assert_eq!(stats.total_bytes_in, 1000);
    }

    #[test]
    fn test_traffic_window_rolling() {
        let mut window = RollingTrafficWindow::new();

        for i in 0..5 {
            window.add_sample(TrafficSnapshot {
                timestamp: Utc::now(),
                bytes_in: 100 * (i + 1),
                bytes_out: 50 * (i + 1),
                connection_count: i as usize + 1,
            });
        }

        assert_eq!(window.hour_samples.len(), 5);
        assert!(window.avg_bytes_in_per_min() > 0.0);
        assert!(window.avg_bytes_out_per_min() > 0.0);
    }

    #[test]
    fn test_new_destination_detection() {
        let mut tracker = NetworkTracker::new();

        tracker.register_connection(
            1234,
            "test-agent".to_string(),
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            9000,
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            443,
            Protocol::Tcp,
            ConnectionState::Established,
            100,
            50,
        );

        assert!(!tracker.is_new_destination(1234, "93.184.216.34", 443, "tcp"));
        assert!(tracker.is_new_destination(1234, "1.2.3.4", 8080, "tcp"));
    }

    #[test]
    fn test_socket_addr_parsing() {
        // 0100007F:0035 -> 127.0.0.1:53
        let (ip, port) = parse_socket_addr("0100007F:0035");
        assert_eq!(ip, "127.0.0.1");
        assert_eq!(port, 53);
    }

    #[test]
    fn test_tcp_state_parsing() {
        assert_eq!(parse_tcp_state("01"), ConnectionState::Established);
        assert_eq!(parse_tcp_state("0A"), ConnectionState::Listen);
        assert_eq!(parse_tcp_state("06"), ConnectionState::Unknown("06".to_string()));
    }

    #[test]
    fn test_prune_stale_connections() {
        let mut tracker = NetworkTracker::new();

        tracker.register_connection(
            1234,
            "agent".to_string(),
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            9000,
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            80,
            Protocol::Tcp,
            ConnectionState::Established,
            100,
            50,
        );

        // Remove with a negative max age (should prune everything)
        tracker.prune_stale_connections(-1);
        assert_eq!(tracker.connection_count(), 0);
    }

    #[test]
    fn test_destination_tracking_by_pid() {
        let mut tracker = NetworkTracker::new();

        tracker.register_connection(
            1,
            "agent-a".to_string(),
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            9000,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            443,
            Protocol::Tcp,
            ConnectionState::Established,
            0,
            0,
        );

        tracker.register_connection(
            2,
            "agent-b".to_string(),
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            9001,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            80,
            Protocol::Tcp,
            ConnectionState::Established,
            0,
            0,
        );

        assert_eq!(tracker.get_connections_for_pid(1).len(), 1);
        assert_eq!(tracker.get_connections_for_pid(2).len(), 1);
        assert_eq!(tracker.connection_count(), 2);
    }
}
