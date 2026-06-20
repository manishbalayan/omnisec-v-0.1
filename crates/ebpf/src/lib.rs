//! # OMNISEC eBPF Userspace Loader & Event Processor
//!
//! Loads eBPF programs into the kernel, reads ring buffer events,
//! resolves PIDs to agent identities, and publishes structured events to NATS.
//!
//! Architecture:
//! ```
//! eBPF kernel programs (tracepoints)
//!   ↓ Ring Buffer (mmap'd shared memory)
//! eBPF userspace (this crate)
//!   ↓ PID → Agent (through AgentIdentityEngine)
//!   ↓ NATS (structured events)
//! Daemon Task 9 (kernel event stream)
//! ```
//!
//! Fallback: When eBPF is unavailable (macOS, no CAP_BPF, old kernel),
//! a /proc-based polling fallback provides similar data at lower fidelity.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use chrono::Utc;
use omnisec_ebpf_common::*;
use omnisec_events::subjects;
use omnisec_messaging::NatsClient;
use serde::Serialize;
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, info, warn};

// =========================================================================
// Native eBPF types (Linux only)
// =========================================================================

#[cfg(target_os = "linux")]
use aya::{
    programs::{TracePoint, KProbe, XdpLink},
    util::online_cpus,
    maps::{MapRefMut, RingBuf},
    Ebpf, Btf,
};

// =========================================================================
// Event bus — userspace channel for processed events
// =========================================================================

/// Processed kernel event ready for NATS publishing
#[derive(Debug, Clone)]
pub enum KernelEvent {
    ProcessExec(ProcessExecEvent),
    ProcessExit(ProcessExitEvent),
    ProcessFork(ProcessForkEvent),
    NetworkConnect(NetworkConnectEvent),
    NetworkListen(NetworkListenEvent),
    NetworkAccept(NetworkAcceptEvent),
    FileAccess(FileAccessEvent),
    FileDelete(FileDeleteEvent),
    FileModify(FileModifyEvent),
    DnsQuery(DnsQueryEvent),
}

#[derive(Debug, Clone, Serialize)]
pub struct ProcessExecEvent {
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub comm: String,
    pub filename: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub agent_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProcessExitEvent {
    pub pid: u32,
    pub exit_code: i32,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProcessForkEvent {
    pub parent_pid: u32,
    pub child_pid: u32,
    pub comm: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize)]
pub struct NetworkConnectEvent {
    pub pid: u32,
    pub dest_ip: String,
    pub dest_port: u16,
    pub src_ip: String,
    pub src_port: u16,
    pub protocol: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub agent_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct NetworkListenEvent {
    pub pid: u32,
    pub ip: String,
    pub port: u16,
    pub protocol: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize)]
pub struct NetworkAcceptEvent {
    pub pid: u32,
    pub client_ip: String,
    pub client_port: u16,
    pub server_ip: String,
    pub server_port: u16,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FileAccessEvent {
    pub pid: u32,
    pub path: String,
    pub operation: String,
    pub flags: u32,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub sensitive_match: bool,
    pub agent_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FileDeleteEvent {
    pub pid: u32,
    pub path: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FileModifyEvent {
    pub pid: u32,
    pub path: String,
    pub operation: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DnsQueryEvent {
    pub pid: u32,
    pub domain: String,
    pub query_type: String,
    pub resolver_ip: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

// =========================================================================
// Event statistics
// =========================================================================

#[derive(Debug, Clone, Default)]
pub struct EbpfStats {
    pub events_total: u64,
    pub process_exec_count: u64,
    pub process_exit_count: u64,
    pub process_fork_count: u64,
    pub network_connect_count: u64,
    pub network_listen_count: u64,
    pub network_accept_count: u64,
    pub file_access_count: u64,
    pub file_delete_count: u64,
    pub file_modify_count: u64,
    pub dns_query_count: u64,
    pub dropped_events: u64,
    pub read_errors: u64,
    pub ebpf_loaded: bool,
    pub using_fallback: bool,
    pub avg_latency_us: f64,
}

// =========================================================================
// Kernel Event Stream — channel between eBPF readers and daemon
// =========================================================================

/// The event stream that collects kernel events and makes them available
/// to the daemon via an mpsc channel.
pub struct KernelEventStream {
    tx: mpsc::UnboundedSender<KernelEvent>,
    pub stats: Arc<RwLock<EbpfStats>>,
}

impl KernelEventStream {
    pub fn new() -> (Self, mpsc::UnboundedReceiver<KernelEvent>) {
        let (tx, rx) = mpsc::unbounded_channel();
        let stream = Self {
            stats: Arc::new(RwLock::new(EbpfStats::default())),
            tx,
        };
        (stream, rx)
    }

    pub fn get_sender(&self) -> mpsc::UnboundedSender<KernelEvent> {
        self.tx.clone()
    }
}

// =========================================================================
// eBPF Manager — full rewrite with real Aya integration
// =========================================================================

pub struct EbpfManager {
    /// Whether eBPF programs are loaded in the kernel
    loaded: bool,
    /// Whether we're using /proc fallback instead of eBPF
    using_fallback: bool,
    /// Ring buffer readers — one per CPU per map
    #[cfg(target_os = "linux")]
    process_ring_bufs: Vec<RingBuf<MapRefMut>>,
    #[cfg(target_os = "linux")]
    network_ring_bufs: Vec<RingBuf<MapRefMut>>,
    #[cfg(target_os = "linux")]
    file_ring_bufs: Vec<RingBuf<MapRefMut>>,
    #[cfg(target_os = "linux")]
    dns_ring_bufs: Vec<RingBuf<MapRefMut>>,
    /// eBPF object
    #[cfg(target_os = "linux")]
    bpf: Option<Ebpf>,
    /// Event statistics
    stats: Arc<RwLock<EbpfStats>>,
    /// NATS client for publishing
    nats: Option<Arc<NatsClient>>,
    /// Identity engine reference
    identity: Option<Arc<RwLock<omnisec_identity::AgentIdentityEngine>>>,
    /// Network tracker for /proc fallback
    network_tracker: Option<Arc<RwLock<omnisec_network::NetworkTracker>>>,
    /// Event channel to daemon
    event_tx: Option<mpsc::UnboundedSender<KernelEvent>>,
    /// Whether fallback monitoring task is running
    fallback_running: bool,
}

impl EbpfManager {
    pub fn new() -> Self {
        Self {
            loaded: false,
            using_fallback: false,
            stats: Arc::new(RwLock::new(EbpfStats::default())),
            nats: None,
            identity: None,
            network_tracker: None,
            event_tx: None,
            fallback_running: false,
            #[cfg(target_os = "linux")]
            process_ring_bufs: Vec::new(),
            #[cfg(target_os = "linux")]
            network_ring_bufs: Vec::new(),
            #[cfg(target_os = "linux")]
            file_ring_bufs: Vec::new(),
            #[cfg(target_os = "linux")]
            dns_ring_bufs: Vec::new(),
            #[cfg(target_os = "linux")]
            bpf: None,
        }
    }

    /// Attach the NATS client and identity engine for publishing resolved events
    pub fn with_nats(mut self, nats: Arc<NatsClient>) -> Self {
        self.nats = Some(nats);
        self
    }

    pub fn with_identity(mut self, identity: Arc<RwLock<omnisec_identity::AgentIdentityEngine>>) -> Self {
        self.identity = Some(identity);
        self
    }

    pub fn with_network_tracker(mut self, tracker: Arc<RwLock<omnisec_network::NetworkTracker>>) -> Self {
        self.network_tracker = Some(tracker);
        self
    }

    pub fn with_event_channel(mut self, tx: mpsc::UnboundedSender<KernelEvent>) -> Self {
        self.event_tx = Some(tx);
        self
    }

    // -----------------------------------------------------------------------
    // Load eBPF programs into the kernel
    // -----------------------------------------------------------------------

    pub async fn load_programs(&mut self) -> Result<()> {
        info!("Loading eBPF programs");

        #[cfg(target_os = "linux")]
        {
            match self.load_aya_programs().await {
                Ok(()) => {
                    info!("eBPF programs loaded successfully (Aya)");
                    self.loaded = true;
                    self.using_fallback = false;

                    let mut stats = self.stats.write().await;
                    stats.ebpf_loaded = true;
                    stats.using_fallback = false;

                    // Start the ring buffer reader tasks
                    self.start_ring_buffer_readers();
                    return Ok(());
                }
                Err(e) => {
                    warn!("Failed to load Aya eBPF programs: {}. Falling back to /proc monitoring.", e);
                }
            }
        }

        // Fallback path: macOS or Linux without eBPF capabilities
        #[cfg(not(target_os = "linux"))]
        {
            warn!("eBPF not supported on this platform — using /proc fallback monitoring");
        }

        self.loaded = true;
        self.using_fallback = true;

        {
            let mut stats = self.stats.write().await;
            stats.ebpf_loaded = false;
            stats.using_fallback = true;
        } // drop stats borrow before self call

        // Start fallback monitoring
        if !self.fallback_running {
            self.start_fallback_monitoring();
        }

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Aya eBPF program loader (Linux only)
    // -----------------------------------------------------------------------

    #[cfg(target_os = "linux")]
    async fn load_aya_programs(&mut self) -> Result<()> {
        // Load the compiled BPF ELF file
        let bpf_bytes = include_bytes_aligned!(concat!(env!("OUT_DIR"), "/omnisec-ebpf-bpf"));
        let mut bpf = Ebpf::load(bpf_bytes)?;

        // --- Load tracepoint: sched_process_exec ---
        let program: &mut TracePoint = bpf.program_mut("sched_process_exec")?
            .try_into()?;
        program.load()?;
        program.attach("sched", "sched_process_exec")?;
        info!("Attached sched_process_exec tracepoint");

        // --- Load tracepoint: sched_process_exit ---
        let program: &mut TracePoint = bpf.program_mut("sched_process_exit")?
            .try_into()?;
        program.load()?;
        program.attach("sched", "sched_process_exit")?;
        info!("Attached sched_process_exit tracepoint");

        // --- Load tracepoint: sys_enter_clone ---
        let program: &mut TracePoint = bpf.program_mut("sys_enter_clone")?
            .try_into()?;
        program.load()?;
        program.attach("syscalls", "sys_enter_clone")?;
        info!("Attached sys_enter_clone tracepoint");

        // --- Load tracepoint: sys_enter_connect ---
        let program: &mut TracePoint = bpf.program_mut("sys_enter_connect")?
            .try_into()?;
        program.load()?;
        program.attach("syscalls", "sys_enter_connect")?;
        info!("Attached sys_enter_connect tracepoint");

        // --- Load tracepoint: sys_enter_bind ---
        let program: &mut TracePoint = bpf.program_mut("sys_enter_bind")?
            .try_into()?;
        program.load()?;
        program.attach("syscalls", "sys_enter_bind")?;
        info!("Attached sys_enter_bind tracepoint");

        // --- Load tracepoint: sys_enter_accept4 ---
        let program: &mut TracePoint = bpf.program_mut("sys_enter_accept4")?
            .try_into()?;
        program.load()?;
        program.attach("syscalls", "sys_enter_accept4")?;
        info!("Attached sys_enter_accept4 tracepoint");

        // --- Load tracepoint: sys_enter_openat ---
        let program: &mut TracePoint = bpf.program_mut("sys_enter_openat")?
            .try_into()?;
        program.load()?;
        program.attach("syscalls", "sys_enter_openat")?;
        info!("Attached sys_enter_openat tracepoint");

        // --- Load tracepoint: sys_enter_unlinkat ---
        let program: &mut TracePoint = bpf.program_mut("sys_enter_unlinkat")?
            .try_into()?;
        program.load()?;
        program.attach("syscalls", "sys_enter_unlinkat")?;
        info!("Attached sys_enter_unlinkat tracepoint");

        // --- Load tracepoint: sys_enter_sendto (DNS queries) ---
        let program: &mut TracePoint = bpf.program_mut("sys_enter_sendto")?
            .try_into()?;
        program.load()?;
        program.attach("syscalls", "sys_enter_sendto")?;
        info!("Attached sys_enter_sendto tracepoint (DNS port 53)");

        // Open the ring buffer maps
        let process_map: MapRefMut = bpf.map_mut("PROCESS_EVENTS")?;
        let network_map: MapRefMut = bpf.map_mut("NETWORK_EVENTS")?;
        let file_map: MapRefMut = bpf.map_mut("FILE_EVENTS")?;
        let dns_map: MapRefMut = bpf.map_mut("DNS_EVENTS")?;

        // Create per-CPU ring buffer readers
        let cpus = online_cpus()?;
        for cpu in cpus {
            let rb = RingBuf::try_from(process_map.try_clone()?)?;
            self.process_ring_bufs.push(rb);
        }
        for cpu in cpus.clone() {
            let rb = RingBuf::try_from(network_map.try_clone()?)?;
            self.network_ring_bufs.push(rb);
        }
        for cpu in cpus.clone() {
            let rb = RingBuf::try_from(file_map.try_clone()?)?;
            self.file_ring_bufs.push(rb);
        }
        for _cpu in cpus {
            let rb = RingBuf::try_from(dns_map.try_clone()?)?;
            self.dns_ring_bufs.push(rb);
        }

        self.bpf = Some(bpf);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Ring buffer readers (Linux only)
    // -----------------------------------------------------------------------

    #[cfg(target_os = "linux")]
    fn start_ring_buffer_readers(&mut self) {
        let tx = match &self.event_tx {
            Some(tx) => tx.clone(),
            None => return,
        };
        let stats = self.stats.clone();
        let identity = self.identity.clone();

        // Process events reader
        let ring_bufs = std::mem::take(&mut self.process_ring_bufs);
        let tx_clone = tx.clone();
        let stats_clone = stats.clone();
        let identity_clone = identity.clone();
        tokio::spawn(async move {
            let mut bufs = ring_bufs;
            loop {
                for buf in &mut bufs {
                    while let Some(raw) = buf.next() {
                        if raw.len() < size_of::<ProcessEvent>() {
                            let mut s = stats_clone.write().await;
                            s.read_errors += 1;
                            continue;
                        }
                        let event: ProcessEvent = unsafe { *(raw.as_ptr() as *const ProcessEvent) };

                        // Resolve PID to agent
                        let agent_id = if let Some(ref identity) = identity_clone {
                            let ident = identity.read().await;
                            ident.resolve_pid(event.pid)
                                .map(|i| i.agent_id.to_string())
                        } else {
                            None
                        };

                        let ts = Utc::now();

                        match event.event_type {
                            t if t == EVENT_PROCESS_EXEC as u8 => {
                                let exec_evt = ProcessExecEvent {
                                    pid: event.pid,
                                    ppid: event.ppid,
                                    uid: event.uid,
                                    comm: event.comm_str().to_string(),
                                    filename: event.filename_str().to_string(),
                                    timestamp: ts,
                                    agent_id,
                                };
                                let _ = tx_clone.send(KernelEvent::ProcessExec(exec_evt));
                                let mut s = stats_clone.write().await;
                                s.events_total += 1;
                                s.process_exec_count += 1;
                            }
                            t if t == EVENT_PROCESS_EXIT as u8 => {
                                let exit_evt = ProcessExitEvent {
                                    pid: event.pid,
                                    exit_code: event.exit_code,
                                    timestamp: ts,
                                };
                                let _ = tx_clone.send(KernelEvent::ProcessExit(exit_evt));
                                let mut s = stats_clone.write().await;
                                s.events_total += 1;
                                s.process_exit_count += 1;
                            }
                            t if t == EVENT_PROCESS_FORK as u8 => {
                                let fork_evt = ProcessForkEvent {
                                    parent_pid: event.ppid,
                                    child_pid: event.child_pid,
                                    comm: event.comm_str().to_string(),
                                    timestamp: ts,
                                };
                                let _ = tx_clone.send(KernelEvent::ProcessFork(fork_evt));
                                let mut s = stats_clone.write().await;
                                s.events_total += 1;
                                s.process_fork_count += 1;
                            }
                            _ => {
                                let mut s = stats_clone.write().await;
                                s.dropped_events += 1;
                            }
                        }
                    }
                }
                tokio::time::sleep(Duration::from_micros(100)).await;
            }
        });

        // Network events reader
        let net_ring_bufs = std::mem::take(&mut self.network_ring_bufs);
        let stats_clone = stats.clone();
        tokio::spawn(async move {
            let mut bufs = net_ring_bufs;
            loop {
                for buf in &mut bufs {
                    while let Some(raw) = buf.next() {
                        if raw.len() < size_of::<NetworkEvent>() {
                            let mut s = stats_clone.write().await;
                            s.read_errors += 1;
                            continue;
                        }
                        let event: NetworkEvent = unsafe { *(raw.as_ptr() as *const NetworkEvent) };
                        let ts = Utc::now();

                        let ip_str = format!("{}.{}.{}.{}", event.dest_ip[0], event.dest_ip[1],
                                             event.dest_ip[2], event.dest_ip[3]);
                        let src_ip = format!("{}.{}.{}.{}", event.src_ip[0], event.src_ip[1],
                                             event.src_ip[2], event.src_ip[3]);
                        let proto = match event.protocol {
                            PROTOCOL_TCP => "tcp",
                            PROTOCOL_TCP6 => "tcp6",
                            PROTOCOL_UDP => "udp",
                            _ => "unknown",
                        };

                        match event.event_type {
                            t if t == EVENT_NETWORK_CONNECT as u8 => {
                                let conn_evt = NetworkConnectEvent {
                                    pid: event.pid,
                                    dest_ip: ip_str,
                                    dest_port: event.dest_port,
                                    src_ip,
                                    src_port: event.src_port,
                                    protocol: proto.to_string(),
                                    timestamp: ts,
                                    agent_id: None,
                                };
                                let _ = tx.send(KernelEvent::NetworkConnect(conn_evt));
                                let mut s = stats_clone.write().await;
                                s.events_total += 1;
                                s.network_connect_count += 1;
                            }
                            t if t == EVENT_NETWORK_LISTEN as u8 => {
                                let listen_evt = NetworkListenEvent {
                                    pid: event.pid,
                                    ip: ip_str,
                                    port: event.dest_port,
                                    protocol: proto.to_string(),
                                    timestamp: ts,
                                };
                                let _ = tx.send(KernelEvent::NetworkListen(listen_evt));
                                let mut s = stats_clone.write().await;
                                s.events_total += 1;
                                s.network_listen_count += 1;
                            }
                            t if t == EVENT_NETWORK_ACCEPT as u8 => {
                                let accept_evt = NetworkAcceptEvent {
                                    pid: event.pid,
                                    client_ip: ip_str,
                                    client_port: event.client_port,
                                    server_ip: format!("{}.{}.{}.{}",
                                        event.src_ip[0], event.src_ip[1],
                                        event.src_ip[2], event.src_ip[3]),
                                    server_port: event.server_port,
                                    timestamp: ts,
                                };
                                let _ = tx.send(KernelEvent::NetworkAccept(accept_evt));
                                let mut s = stats_clone.write().await;
                                s.events_total += 1;
                                s.network_accept_count += 1;
                            }
                            _ => {
                                let mut s = stats_clone.write().await;
                                s.dropped_events += 1;
                            }
                        }
                    }
                }
                tokio::time::sleep(Duration::from_micros(100)).await;
            }
        });

        // File events reader
        let file_ring_bufs = std::mem::take(&mut self.file_ring_bufs);
        let stats_clone = stats.clone();
        let identity_clone = identity.clone();
        tokio::spawn(async move {
            let mut bufs = file_ring_bufs;
            loop {
                for buf in &mut bufs {
                    while let Some(raw) = buf.next() {
                        if raw.len() < size_of::<FileEvent>() {
                            let mut s = stats_clone.write().await;
                            s.read_errors += 1;
                            continue;
                        }
                        let event: FileEvent = unsafe { *(raw.as_ptr() as *const FileEvent) };
                        let ts = Utc::now();
                        let path = event.path_str().to_string();
                        let operation = event.operation_str().to_string();

                        // Check for sensitive paths
                        let sensitive_patterns = [
                            "/etc/passwd", "/etc/shadow", "/etc/ssh",
                            ".ssh", ".env", "credentials", "tokens",
                            ".gitconfig", ".aws", ".gcp", "id_rsa",
                        ];
                        let sensitive_match = sensitive_patterns.iter()
                            .any(|p| path.contains(p));

                        let agent_id = if let Some(ref identity) = identity_clone {
                            let ident = identity.read().await;
                            ident.resolve_pid(event.pid)
                                .map(|i| i.agent_id.to_string())
                        } else {
                            None
                        };

                        match event.event_type {
                            t if t == EVENT_FILE_ACCESS as u8 => {
                                let access_evt = FileAccessEvent {
                                    pid: event.pid,
                                    path,
                                    operation,
                                    flags: event.flags,
                                    timestamp: ts,
                                    sensitive_match,
                                    agent_id,
                                };
                                let _ = tx.send(KernelEvent::FileAccess(access_evt));
                                let mut s = stats_clone.write().await;
                                s.events_total += 1;
                                s.file_access_count += 1;
                                if sensitive_match {
                                    warn!("SENSITIVE FILE ACCESS: PID {} accessed {}", event.pid, path);
                                }
                            }
                            t if t == EVENT_FILE_DELETE as u8 => {
                                let del_evt = FileDeleteEvent {
                                    pid: event.pid, path,
                                    timestamp: ts,
                                };
                                let _ = tx.send(KernelEvent::FileDelete(del_evt));
                                let mut s = stats_clone.write().await;
                                s.events_total += 1;
                                s.file_delete_count += 1;
                            }
                            t if t == EVENT_FILE_MODIFY as u8 => {
                                let mod_evt = FileModifyEvent {
                                    pid: event.pid, path, operation,
                                    timestamp: ts,
                                };
                                let _ = tx.send(KernelEvent::FileModify(mod_evt));
                                let mut s = stats_clone.write().await;
                                s.events_total += 1;
                                s.file_modify_count += 1;
                            }
                            _ => {
                                let mut s = stats_clone.write().await;
                                s.dropped_events += 1;
                            }
                        }
                    }
                }
                tokio::time::sleep(Duration::from_micros(100)).await;
            }
        });

        // DNS events reader
        let dns_ring_bufs = std::mem::take(&mut self.dns_ring_bufs);
        tokio::spawn(async move {
            let mut bufs = dns_ring_bufs;
            loop {
                for buf in &mut bufs {
                    while let Some(raw) = buf.next() {
                        if raw.len() < size_of::<DnsEvent>() {
                            continue;
                        }
                        let event: DnsEvent = unsafe { *(raw.as_ptr() as *const DnsEvent) };
                        let ts = Utc::now();
                        let resolver = format!("{}.{}.{}.{}",
                            event.resolver_ip[0], event.resolver_ip[1],
                            event.resolver_ip[2], event.resolver_ip[3]);

                        let dns_evt = DnsQueryEvent {
                            pid: event.pid,
                            domain: format!("hash:{:016x}", event.domain_hash),
                            query_type: match event.dns_type {
                                1 => "A".to_string(),
                                28 => "AAAA".to_string(),
                                15 => "MX".to_string(),
                                _ => format!("TYPE{}", event.dns_type),
                            },
                            resolver_ip: resolver,
                            timestamp: ts,
                        };
                        let _ = tx.send(KernelEvent::DnsQuery(dns_evt));
                        let mut s = stats.write().await;
                        s.events_total += 1;
                        s.dns_query_count += 1;
                    }
                }
                tokio::time::sleep(Duration::from_micros(100)).await;
            }
        });
    }

    // -----------------------------------------------------------------------
    // /proc fallback monitoring (all platforms)
    // -----------------------------------------------------------------------

    fn start_fallback_monitoring(&mut self) {
        self.fallback_running = true;
        let tx = match &self.event_tx {
            Some(tx) => tx.clone(),
            None => return,
        };
        let stats = self.stats.clone();
        let network_tracker = self.network_tracker.clone();
        let identity = self.identity.clone();

        info!("Starting /proc fallback monitoring (1s interval)");

        tokio::spawn(async move {
            let mut prev_pids: std::collections::HashSet<u32> = std::collections::HashSet::new();

            loop {
                // --- Process exec/exit detection via /proc scan diff ---
                let current_pids: std::collections::HashSet<u32> = match std::fs::read_dir("/proc") {
                    Ok(entries) => {
                        entries
                            .filter_map(|e| e.ok())
                            .filter_map(|e| e.file_name().to_string_lossy().parse::<u32>().ok())
                            .collect()
                    }
                    Err(_) => std::collections::HashSet::new(),
                };

                // Detect new processes (exec)
                for &pid in &current_pids {
                    if !prev_pids.contains(&pid) {
                        // Read comm and cmdline
                        let comm = std::fs::read_to_string(format!("/proc/{}/comm", pid))
                            .map(|s| s.trim().to_string())
                            .unwrap_or_default();
                        let cmdline = std::fs::read(format!("/proc/{}/cmdline", pid))
                            .ok()
                            .map(|c| {
                                c.split(|&b| b == 0)
                                    .filter(|s| !s.is_empty())
                                    .map(|s| String::from_utf8_lossy(s).to_string())
                                    .collect::<Vec<_>>()
                                    .join(" ")
                            })
                            .unwrap_or_default();

                        // Get ppid
                        let status = std::fs::read_to_string(format!("/proc/{}/status", pid)).ok();
                        let ppid = status.as_deref()
                            .and_then(|s| s.lines().find(|l| l.starts_with("PPid:")))
                            .and_then(|l| l.split_whitespace().nth(1))
                            .and_then(|s| s.parse::<u32>().ok())
                            .unwrap_or(0);

                        let agent_id = if let Some(ref identity) = identity {
                            let ident = identity.read().await;
                            ident.resolve_pid(pid).map(|i| i.agent_id.to_string())
                        } else {
                            None
                        };

                        let exec_evt = ProcessExecEvent {
                            pid,
                            ppid,
                            uid: 0,
                            comm,
                            filename: cmdline,
                            timestamp: Utc::now(),
                            agent_id,
                        };
                        let _ = tx.send(KernelEvent::ProcessExec(exec_evt));
                        let mut s = stats.write().await;
                        s.events_total += 1;
                        s.process_exec_count += 1;
                    }
                }

                // Detect exited processes
                for &pid in &prev_pids {
                    if !current_pids.contains(&pid) {
                        let exit_evt = ProcessExitEvent {
                            pid,
                            exit_code: -1,
                            timestamp: Utc::now(),
                        };
                        let _ = tx.send(KernelEvent::ProcessExit(exit_evt));
                        let mut s = stats.write().await;
                        s.events_total += 1;
                        s.process_exit_count += 1;
                    }
                }

                prev_pids = current_pids;

                // --- Network connections via /proc/net/tcp ---
                if let Some(ref tracker) = network_tracker {
                    let mut t = tracker.write().await;
                    t.collect_connections();
                }

                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        });
    }

    // -----------------------------------------------------------------------
    // NATS event publishing
    // -----------------------------------------------------------------------

    /// Publish a kernel event to NATS. Call this from the daemon's event loop.
    pub async fn publish_event(&self, event: &KernelEvent) -> Result<()> {
        let nats = match &self.nats {
            Some(n) => n.clone(),
            None => return Ok(()),
        };

        let (subject, payload_value) = match event {
            KernelEvent::ProcessExec(evt) => (subjects::PROCESS_EXEC, serde_json::to_value(evt)?),
            KernelEvent::ProcessExit(evt) => (subjects::PROCESS_EXIT, serde_json::to_value(evt)?),
            KernelEvent::ProcessFork(evt) => (subjects::PROCESS_FORK, serde_json::to_value(evt)?),
            KernelEvent::NetworkConnect(evt) => (subjects::NETWORK_CONNECT, serde_json::to_value(evt)?),
            KernelEvent::NetworkListen(evt) => (subjects::NETWORK_LISTEN, serde_json::to_value(evt)?),
            KernelEvent::NetworkAccept(evt) => (subjects::NETWORK_ACCEPT, serde_json::to_value(evt)?),
            KernelEvent::FileAccess(evt) => (subjects::FILE_ACCESS, serde_json::to_value(evt)?),
            KernelEvent::FileDelete(evt) => (subjects::FILE_DELETE, serde_json::to_value(evt)?),
            KernelEvent::FileModify(evt) => (subjects::FILE_MODIFY, serde_json::to_value(evt)?),
            KernelEvent::DnsQuery(evt) => (subjects::DNS_QUERY, serde_json::to_value(evt)?),
        };

        nats.publish(subject, "ebpf-sensor", payload_value).await
            .map_err(|e| anyhow::anyhow!("Failed to publish kernel event: {}", e))
    }

    // -----------------------------------------------------------------------
    // Stats
    // -----------------------------------------------------------------------

    pub async fn get_stats(&self) -> EbpfStats {
        self.stats.read().await.clone()
    }

    pub fn is_loaded(&self) -> bool {
        self.loaded
    }

    pub fn is_using_fallback(&self) -> bool {
        self.using_fallback
    }

    // -----------------------------------------------------------------------
    // Unload
    // -----------------------------------------------------------------------

    pub async fn unload_programs(&mut self) -> Result<()> {
        info!("Unloading eBPF programs");

        #[cfg(target_os = "linux")]
        {
            self.bpf.take();
            self.process_ring_bufs.clear();
            self.network_ring_bufs.clear();
            self.file_ring_bufs.clear();
            self.dns_ring_bufs.clear();
        }

        self.loaded = false;
        Ok(())
    }
}

impl Default for EbpfManager {
    fn default() -> Self {
        Self::new()
    }
}



// =========================================================================
// Helper macro for embedding BPF bytecode (Linux only)
// =========================================================================

#[cfg(target_os = "linux")]
macro_rules! include_bytes_aligned {
    ($path:expr) => {{
        // BPF bytecode must be aligned to 8 bytes
        const ALIGN: usize = 8;
        static BYTES: &[u8] = include_bytes!($path);
        let len = BYTES.len();
        let padded_len = (len + ALIGN - 1) & !(ALIGN - 1);
        let mut padded = vec![0u8; padded_len];
        padded[..len].copy_from_slice(BYTES);
        padded
    }};
}

#[cfg(not(target_os = "linux"))]
macro_rules! include_bytes_aligned {
    ($path:expr) => {{
        Vec::new()
    }};
}
