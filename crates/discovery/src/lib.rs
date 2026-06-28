use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Cached result of scanning active network connections for LLM traffic.
/// Refreshed at most once every 30 seconds to avoid hammering lsof.
#[derive(Clone)]
struct LlmConnectionCache {
    /// PIDs that currently have an active connection to an LLM provider API.
    pids: HashSet<u32>,
    /// The provider name keyed by PID (e.g. "Anthropic", "OpenAI").
    providers: HashMap<u32, String>,
    refreshed_at: Instant,
}

impl LlmConnectionCache {
    fn empty() -> Self {
        Self {
            pids: HashSet::new(),
            providers: HashMap::new(),
            refreshed_at: Instant::now() - Duration::from_secs(60),
        }
    }
}

/// Well-known LLM provider API hostnames and the provider label to use.
const LLM_PROVIDER_HOSTS: &[(&str, &str)] = &[
    ("api.anthropic.com",                    "Anthropic"),
    ("api.openai.com",                       "OpenAI"),
    ("generativelanguage.googleapis.com",    "Google"),
    ("aiplatform.googleapis.com",            "Google"),
    ("api.cohere.com",                       "Cohere"),
    ("api.cohere.ai",                        "Cohere"),
    ("api.mistral.ai",                       "Mistral"),
    ("api.groq.com",                         "Groq"),
    ("openrouter.ai",                        "OpenRouter"),
    ("api.together.xyz",                     "Together"),
    ("api.deepseek.com",                     "DeepSeek"),
    ("api.x.ai",                             "xAI"),
    ("inference.fireworks.ai",               "Fireworks"),
    ("api.perplexity.ai",                    "Perplexity"),
    ("api.replicate.com",                    "Replicate"),
    ("api-inference.huggingface.co",         "HuggingFace"),
];

/// Returns the proc mount path to use for agent discovery.
/// OmniSec runs host-natively, so this is always the host `/proc`.
pub fn proc_root() -> &'static str {
    "/proc"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredAgent {
    pub pid: u32,
    pub ppid: Option<u32>,
    pub name: String,
    pub command: String,
    pub framework: Option<String>,
    pub model_provider: Option<String>,
    pub memory_mb: Option<f64>,
    pub cpu_percent: Option<f64>,
    pub status: AgentStatus,
    pub env_vars: Vec<String>,
    pub listening_ports: Vec<u16>,
    pub confidence: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AgentStatus {
    Running,
    Idle,
    Unknown,
}

pub struct AgentDiscovery {
    known_frameworks: Vec<FrameworkPattern>,
    llm_conn_cache: Arc<Mutex<LlmConnectionCache>>,
}

struct FrameworkPattern {
    name: String,
    process_patterns: Vec<String>,
    command_patterns: Vec<String>,
    env_indicators: Vec<String>,
}

impl Default for AgentDiscovery {
    fn default() -> Self {
        Self::new()
    }
}

impl AgentDiscovery {
    pub fn new() -> Self {
        Self {
            known_frameworks: Self::build_framework_patterns(),
            llm_conn_cache: Arc::new(Mutex::new(LlmConnectionCache::empty())),
        }
    }

    /// Known sensitive environment variable patterns that should never be exposed.
    /// These are matched by key prefix — any env var whose key contains these
    /// substrings will be dropped from API responses.
    const SENSITIVE_ENV_PATTERNS: &[&str] = &[
        "API_KEY", "SECRET", "TOKEN", "PASSWORD", "CREDENTIAL",
        "PRIVATE_KEY", "AUTH", "ACCESS_KEY", "SESSION",
    ];

    fn build_framework_patterns() -> Vec<FrameworkPattern> {
        vec![
            FrameworkPattern {
                name: "Claude Code".to_string(),
                process_patterns: vec!["claude".to_string(), "claude-code".to_string()],
                command_patterns: vec!["claude".to_string(), "anthropic".to_string()],
                env_indicators: vec!["ANTHROPIC_API_KEY".to_string(), "CLAUDE".to_string()],
            },
            FrameworkPattern {
                name: "Hermes".to_string(),
                process_patterns: vec!["hermes".to_string()],
                command_patterns: vec!["hermes_cli".to_string(), "hermes-agent".to_string(), ".hermes/".to_string(), "hermes.app".to_string()],
                env_indicators: vec!["HERMES".to_string()],
            },
            FrameworkPattern {
                name: "OpenClaw".to_string(),
                process_patterns: vec!["openclaw".to_string()],
                command_patterns: vec!["openclaw".to_string(), ".openclaw/".to_string()],
                env_indicators: vec!["OPENCLAW".to_string()],
            },
            FrameworkPattern {
                name: "Cursor".to_string(),
                process_patterns: vec!["cursor".to_string()],
                command_patterns: vec!["cursor".to_string(), ".cursor/".to_string()],
                env_indicators: vec!["CURSOR".to_string()],
            },
            FrameworkPattern {
                name: "Windsurf".to_string(),
                process_patterns: vec!["windsurf".to_string(), "codeium".to_string()],
                command_patterns: vec!["windsurf".to_string(), "codeium".to_string()],
                env_indicators: vec!["CODEIUM".to_string()],
            },
            FrameworkPattern {
                name: "Aider".to_string(),
                process_patterns: vec!["aider".to_string()],
                command_patterns: vec!["aider".to_string()],
                env_indicators: vec!["AIDER".to_string()],
            },
            FrameworkPattern {
                name: "CrewAI".to_string(),
                process_patterns: vec!["crew".to_string(), "crewai".to_string()],
                command_patterns: vec!["crewai".to_string(), "crew_ai".to_string()],
                env_indicators: vec!["CREWAI".to_string()],
            },
            FrameworkPattern {
                name: "LangGraph".to_string(),
                process_patterns: vec!["langgraph".to_string(), "lang_chain".to_string()],
                command_patterns: vec!["langgraph".to_string(), "langchain".to_string()],
                env_indicators: vec!["LANGCHAIN".to_string(), "LANGGRAPH".to_string()],
            },
            FrameworkPattern {
                name: "AutoGen".to_string(),
                process_patterns: vec!["autogen".to_string()],
                command_patterns: vec!["autogen".to_string(), "pyautogen".to_string()],
                env_indicators: vec!["AUTOGEN".to_string()],
            },
            FrameworkPattern {
                name: "OpenAI Agents SDK".to_string(),
                process_patterns: vec!["openai".to_string()],
                command_patterns: vec!["openai".to_string(), "agents-sdk".to_string()],
                env_indicators: vec!["OPENAI_API_KEY".to_string()],
            },
            FrameworkPattern {
                name: "Docker Agent".to_string(),
                process_patterns: vec!["docker".to_string(), "container".to_string()],
                command_patterns: vec!["docker".to_string(), "docker-compose".to_string()],
                env_indicators: vec!["DOCKER".to_string()],
            },
            FrameworkPattern {
                name: "Python Agent".to_string(),
                process_patterns: vec!["python".to_string(), "python3".to_string(), "pip".to_string()],
                command_patterns: vec!["python".to_string(), "python3".to_string()],
                env_indicators: vec!["VIRTUAL_ENV".to_string(), "PYTHON".to_string()],
            },
            FrameworkPattern {
                name: "Node Agent".to_string(),
                process_patterns: vec!["node".to_string(), "npm".to_string(), "npx".to_string()],
                command_patterns: vec!["node".to_string(), "npm".to_string(), "npx".to_string()],
                env_indicators: vec!["NODE".to_string(), "NPM".to_string()],
            },
        ]
    }

    pub fn discover_agents(&self) -> Result<Vec<DiscoveredAgent>> {
        #[cfg(target_os = "linux")]
        {
            return self.discover_linux();
        }

        #[cfg(target_os = "macos")]
        {
            self.discover_macos()
        }

        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            tracing::warn!("Agent discovery not supported on this platform");
            Ok(Vec::new())
        }
    }

    #[cfg(target_os = "linux")]
    fn discover_linux(&self) -> Result<Vec<DiscoveredAgent>> {
        use std::fs;

        let mut agents = Vec::new();

        let proc_path = crate::proc_root();

        for entry in fs::read_dir(proc_path)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().to_string();

            if let Ok(pid) = name.parse::<u32>() {
                if let Some(agent) = self.parse_proc_entry(pid) {
                    agents.push(agent);
                }
            }
        }

        Ok(agents)
    }

    #[cfg(target_os = "linux")]
    fn parse_proc_entry(&self, pid: u32) -> Option<DiscoveredAgent> {
        use std::fs;
        let proc = crate::proc_root();

        let comm = fs::read_to_string(format!("{}/{}/comm", proc, pid)).ok()?;
        let cmdline = fs::read_to_string(format!("{}/{}/cmdline", proc, pid)).ok()?;
        let stat = fs::read_to_string(format!("{}/{}/stat", proc, pid)).ok()?;

        let comm = comm.trim().to_string();
        let cmdline = cmdline.replace('\0', " ");
        let stat_fields: Vec<&str> = stat.split_whitespace().collect();

        if stat_fields.len() < 24 {
            return None;
        }

        let ppid: Option<u32> = stat_fields.get(1).and_then(|s| s.parse().ok());
        // utime (field 13) + stime (field 14) = cumulative CPU ticks
        let utime: f64 = stat_fields.get(13).and_then(|s| s.parse().ok()).unwrap_or(0.0);
        let stime: f64 = stat_fields.get(14).and_then(|s| s.parse().ok()).unwrap_or(0.0);
        let cpu_ticks = utime + stime;
        // Estimate CPU percentage as a fraction of system uptime
        let cpu_percent = estimate_cpu_percentage(cpu_ticks);
        // RSS is field 24 (0-indexed) in /proc/pid/stat
        let rss_pages: f64 = stat_fields.get(23).and_then(|s| s.parse().ok()).unwrap_or(0.0);
        let memory_mb = rss_pages * 4.0 / 1024.0;

        let raw_env_vars = self.get_env_vars(pid);
        let env_vars = self.filter_sensitive_env_vars(&raw_env_vars);
        let listening_ports = self.get_listening_ports(pid);

        let framework = self.detect_framework(&comm, &cmdline, &env_vars);
        let model_provider = self.detect_model_provider(&cmdline, &raw_env_vars);

        let confidence = self.calculate_confidence(&comm, &cmdline, &raw_env_vars, &framework, &model_provider, cpu_ticks);

        Some(DiscoveredAgent {
            pid,
            ppid,
            name: comm,
            command: cmdline,
            framework,
            model_provider,
            memory_mb: Some(memory_mb),
            cpu_percent: Some(cpu_percent),
            status: AgentStatus::Running,
            env_vars,
            listening_ports,
            confidence,
        })
    }

    #[cfg(target_os = "macos")]
    fn discover_macos(&self) -> Result<Vec<DiscoveredAgent>> {
        use std::process::Command;

        // Refresh LLM connection cache (no-op if refreshed within the last 30s).
        self.refresh_llm_connections();

        // -ww: no truncation. = suffix on each field suppresses the header row.
        // Fields: pid, ppid, %cpu, rss (KB), comm (basename ≤15 chars), args (full argv).
        let output = Command::new("ps")
            .args(["-axwwo", "pid=,ppid=,pcpu=,rss=,comm=,args="])
            .output()?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut agents = Vec::new();

        for line in stdout.lines() {
            // split_whitespace() handles leading/trailing spaces and collapsed runs.
            let mut tokens = line.split_whitespace();

            let pid: u32 = match tokens.next().and_then(|s| s.parse().ok()) {
                Some(p) => p,
                None => continue,
            };
            let ppid: u32 = match tokens.next().and_then(|s| s.parse().ok()) {
                Some(p) => p,
                None => continue,
            };
            let cpu_percent: f64 = tokens.next().and_then(|s| s.parse().ok()).unwrap_or(0.0);
            let rss_kb: f64 = tokens.next().and_then(|s| s.parse().ok()).unwrap_or(0.0);
            let comm = match tokens.next() {
                Some(s) => s.to_string(),
                None => continue,
            };
            // Remaining tokens form the full command line (argv joined).
            let args_tokens: Vec<&str> = tokens.collect();
            let cmdline = if args_tokens.is_empty() {
                comm.clone()
            } else {
                args_tokens.join(" ")
            };

            // Skip kernel threads and infrastructure processes that are never AI agents.
            if self.is_infrastructure(&comm, &cmdline) {
                continue;
            }

            // Use the basename of argv[0] as the display name.
            // comm is truncated to 15 chars on macOS; the full path is in cmdline's first token.
            let display_name = cmdline
                .split_whitespace()
                .next()
                .and_then(|s| s.rsplit('/').next())
                .filter(|s| !s.is_empty())
                .unwrap_or(&comm)
                .to_string();

            // Raw env var names are needed for API-key-based detection in confidence scoring.
            // We filter sensitive keys before storing/returning — detection happens first.
            let raw_env_vars = self.get_env_vars(pid);
            let filtered_env = self.filter_sensitive_env_vars(&raw_env_vars);
            let framework = self.detect_framework(&display_name, &cmdline, &filtered_env);
            let mut model_provider = self.detect_model_provider(&cmdline, &raw_env_vars);
            let cpu_ticks_proxy = cpu_percent * 100.0;
            let mut confidence = self.calculate_confidence(
                &display_name, &cmdline, &raw_env_vars, &framework, &model_provider, cpu_ticks_proxy,
            );

            // Network signal: if this PID has an active HTTPS connection to an LLM
            // provider right now, it is almost certainly an AI agent (+55).
            // This is the most reliable signal for custom agents that store keys in
            // config files rather than environment variables.
            {
                let cache = self.llm_conn_cache.lock().unwrap();
                if cache.pids.contains(&pid) {
                    confidence = confidence.saturating_add(55).min(100);
                    if model_provider.is_none() {
                        model_provider = cache.providers.get(&pid).cloned();
                    }
                }
            }

            agents.push(DiscoveredAgent {
                pid,
                ppid: Some(ppid),
                name: display_name,
                command: cmdline,
                framework,
                model_provider,
                memory_mb: Some(rss_kb / 1024.0),
                cpu_percent: Some(cpu_percent),
                status: AgentStatus::Running,
                env_vars: filtered_env,
                listening_ports: vec![],
                confidence,
            });
        }

        // Deduplicate: if a process's parent is ALSO above the confidence threshold
        // in this scan, discard the child. This collapses framework worker pools
        // (Hermes slash_workers, Ollama llama-server forks) without accidentally
        // dropping agents whose parent is a shell or terminal (confidence=0).
        let min_confidence = 30u8;
        let qualified_pids: std::collections::HashSet<u32> = agents
            .iter()
            .filter(|a| a.confidence >= min_confidence)
            .map(|a| a.pid)
            .collect();
        agents.retain(|a| {
            if a.confidence < min_confidence {
                return false; // drop below-threshold entries entirely
            }
            match a.ppid {
                Some(ppid) if qualified_pids.contains(&ppid) => false, // parent is AI agent → child
                _ => true,
            }
        });

        // Name-based deduplication: keep only the highest-confidence entry per process
        // name. This collapses Ollama llama-server workers (re-parented to PID 1 by macOS,
        // so tree dedup can't catch them) into a single representative entry.
        let mut seen_names: HashMap<String, usize> = HashMap::new();
        let mut name_deduped = Vec::with_capacity(agents.len());
        for agent in agents {
            let name_lower = agent.name.to_lowercase();
            match seen_names.get(&name_lower) {
                None => {
                    seen_names.insert(name_lower, name_deduped.len());
                    name_deduped.push(agent);
                }
                Some(&idx) => {
                    // Replace previous entry if this one has higher confidence.
                    if agent.confidence > name_deduped[idx].confidence {
                        name_deduped[idx] = agent;
                    }
                }
            }
        }

        Ok(name_deduped)
    }

    fn get_env_vars(&self, pid: u32) -> Vec<String> {
        #[cfg(target_os = "linux")]
        {
            return self._get_env_vars_linux(pid);
        }
        #[cfg(target_os = "macos")]
        {
            return self._get_env_vars_macos(pid);
        }
        #[allow(unused_variables)]
        let _ = pid;
        vec![]
    }

    /// Read env var keys from sysctl KERN_PROCARGS2 on macOS.
    /// The buffer layout is: argc(i32) + execpath\0 + argv\0... + env\0...
    /// We skip past argc and all argv entries, then collect KEY= prefixes.
    #[cfg(target_os = "macos")]
    fn _get_env_vars_macos(&self, pid: u32) -> Vec<String> {
        use libc::{c_int, c_void, size_t};
        const ARG_MAX: usize = 256 * 1024;
        let mut mib: [c_int; 3] = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid as c_int];
        let mut size: size_t = ARG_MAX;
        let mut buf = vec![0u8; ARG_MAX];
        let ret = unsafe {
            libc::sysctl(
                mib.as_mut_ptr(), 3,
                buf.as_mut_ptr() as *mut c_void, &mut size,
                std::ptr::null_mut(), 0,
            )
        };
        if ret != 0 || size < 4 { return vec![]; }
        buf.truncate(size);

        let argc = i32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]).max(0) as usize;
        let segments: Vec<&[u8]> = buf[4..].split(|&b| b == 0).collect();

        // Skip execpath (1) + argc argv entries; everything after is env.
        let env_start = 1 + argc;
        segments.iter()
            .skip(env_start)
            .filter_map(|s| {
                if s.is_empty() { return None; }
                // Only return the KEY portion (before '=')
                let s = std::str::from_utf8(s).ok()?;
                Some(s.splitn(2, '=').next().unwrap_or(s).to_string())
            })
            .take(256) // cap to avoid scanning gigantic envs
            .collect()
    }

    /// Returns true for kernel threads and infrastructure processes that should
    /// never appear in agent discovery results.
    fn is_infrastructure(&self, comm: &str, cmdline: &str) -> bool {
        let comm_lower = comm.to_lowercase();
        let cmdline_lower = cmdline.to_lowercase();

        // Exact infrastructure process names
        const INFRA_EXACT: &[&str] = &[
            "postgres", "nats-server", "supervisord", "launchd",
            "kernel_task", "syslogd", "configd", "notifyd", "diskarbitrationd",
            "windowserver", "loginwindow", "coreaudiod", "corebluetooth",
            "coreservicesd", "trustd", "securityd", "authd", "opendirectoryd",
            "mdworker", "mds", "mds_stores", "spotlight", "revisiond",
            "spindump", "ReportCrash", "com.apple", "distnoted", "lsd",
            "ctkahp", "nsurlsessiond", "sharingd", "rapportd",
        ];

        if INFRA_EXACT.iter().any(|p| comm_lower.starts_with(p)) {
            return true;
        }

        // OmniSec's own processes
        if comm_lower.contains("omnisec") || cmdline_lower.contains("omnisec") {
            return true;
        }

        // next-server (Next.js dashboard) and similar build tools
        if comm_lower == "next-server" || cmdline_lower.contains("next-server") {
            return true;
        }

        false
    }

    #[cfg(target_os = "linux")]
    fn _get_env_vars_linux(&self, pid: u32) -> Vec<String> {
        use std::fs;
        let proc = crate::proc_root();

        let env_path = format!("{}/{}/environ", proc, pid);
        if let Ok(content) = fs::read(&env_path) {
            let content = String::from_utf8_lossy(&content);
            content
                .split('\0')
                .filter_map(|s| {
                    let parts: Vec<&str> = s.splitn(2, '=').collect();
                    if !parts.is_empty() {
                        Some(parts[0].to_string())
                    } else {
                        None
                    }
                })
                .collect()
        } else {
            vec![]
        }
    }

    #[cfg(target_os = "linux")]
    fn get_listening_ports(&self, pid: u32) -> Vec<u16> {
        use std::fs;
        let proc = crate::proc_root();

        let mut ports = Vec::new();
        let tcp_path = format!("{}/{}/net/tcp", proc, pid);
        let udp_path = format!("{}/{}/net/udp", proc, pid);

        for path in &[tcp_path, udp_path] {
            if let Ok(content) = fs::read_to_string(path) {
                for line in content.lines().skip(1) {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 2 {
                        if let Some(local_addr) = parts.get(1) {
                            let port_hex = local_addr.split(':').next_back().unwrap_or("0");
                            if let Ok(port) = u16::from_str_radix(port_hex, 16) {
                                if port > 0 && !ports.contains(&port) {
                                    ports.push(port);
                                }
                            }
                        }
                    }
                }
            }
        }

        ports
    }

    fn detect_framework(&self, comm: &str, cmdline: &str, env_vars: &[String]) -> Option<String> {
        let comm_lower = comm.to_lowercase();
        let cmdline_lower = cmdline.to_lowercase();

        for framework in &self.known_frameworks {
            for pattern in &framework.process_patterns {
                if comm_lower.contains(pattern) {
                    return Some(framework.name.clone());
                }
            }

            for pattern in &framework.command_patterns {
                if cmdline_lower.contains(pattern) {
                    return Some(framework.name.clone());
                }
            }

            for env in env_vars {
                for indicator in &framework.env_indicators {
                    if env.contains(indicator) {
                        return Some(framework.name.clone());
                    }
                }
            }
        }

        None
    }

    /// Filter sensitive environment variable keys before exposing them.
    /// Drops any env var whose key matches known sensitive patterns
    /// (API keys, tokens, passwords, etc.) — these are never returned.
    /// This prevents leaking which credentials a process has access to.
    fn filter_sensitive_env_vars(&self, env_vars: &[String]) -> Vec<String> {
        env_vars
            .iter()
            .filter(|var| {
                let key = var.splitn(2, '=').next().unwrap_or(var);
                !Self::SENSITIVE_ENV_PATTERNS
                    .iter()
                    .any(|pat| key.to_uppercase().contains(pat))
            })
            .cloned()
            .collect()
    }

    /// Calculate an agent confidence score (0–100) based on multiple signals.
    /// This is the primary classification mechanism — framework detection is
    /// only used as metadata, not as the definitive classification.
    /// Score a process purely on behavioral signals, not on knowing its name.
    /// A custom agent with no known name will still be detected if it:
    ///   - Has an LLM API key in its environment
    ///   - Passes a model name on its command line
    ///   - Imports a known AI framework module
    ///   - Calls an LLM provider API endpoint
    ///
    /// The `raw_env_vars` parameter must be the UNFILTERED list of env var names
    /// so that API key presence can be detected before they are redacted.
    fn calculate_confidence(
        &self,
        comm: &str,
        cmdline: &str,
        raw_env_vars: &[String],
        framework: &Option<String>,
        model_provider: &Option<String>,
        cpu_ticks: f64,
    ) -> u8 {
        let mut score: u8 = 0;
        let comm_lower = comm.to_lowercase();
        let cmdline_lower = cmdline.to_lowercase();

        // Signal 0: The AI framework's own code is being executed (+35).
        // We check the ARGUMENTS portion (after argv[0]) so that a user's script that
        // merely happens to use an AI app's interpreter binary doesn't falsely match.
        // Example: `~/.hermes/node/bin/node ~/myproject/app.js` → no match (user project)
        //          `~/.hermes/node/bin/node ~/.hermes/openclaw/index.js` → match (AI code)
        const AI_INSTALL_PATHS: &[&str] = &[
            "/.hermes/", "/.openclaw/", "/.cursor/", "/.continue/",
            "/.aider/", "/.codeium/", "/.windsurf/",
            "/hermes-agent/", "/openclaw/", "/.devin/", "/.opendevin/",
        ];
        let args_after_binary = cmdline.split_whitespace().skip(1).collect::<Vec<_>>().join(" ");
        let args_lower = args_after_binary.to_lowercase();
        if AI_INSTALL_PATHS.iter().any(|d| args_lower.contains(d)) {
            score = score.saturating_add(35);
        }

        // Signal 1: LLM API key present in environment (+50)
        // This is the strongest signal: any process holding an LLM provider key
        // is almost certainly an AI agent, regardless of what it's called.
        const LLM_API_KEY_PATTERNS: &[&str] = &[
            "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GEMINI_API_KEY",
            "COHERE_API_KEY", "MISTRAL_API_KEY", "GROQ_API_KEY",
            "HUGGINGFACE_TOKEN", "HF_TOKEN", "TOGETHER_API_KEY",
            "REPLICATE_API_TOKEN", "FIREWORKS_API_KEY", "PERPLEXITY_API_KEY",
            "XAI_API_KEY", "DEEPSEEK_API_KEY", "OPENROUTER_API_KEY",
        ];
        if raw_env_vars.iter().any(|v| LLM_API_KEY_PATTERNS.iter().any(|p| v.to_uppercase() == *p)) {
            score = score.saturating_add(50);
        }

        // Signal 2: LLM model name appears in command line (+25)
        // Passing a specific model name as an argument is a strong behavioral signal.
        const MODEL_NAMES: &[&str] = &[
            "claude", "gpt-4", "gpt-3", "gpt4", "gemini", "llama", "mistral",
            "phi-", "qwen", "deepseek", "codestral", "mixtral", "falcon",
            "openai", "anthropic",
        ];
        if MODEL_NAMES.iter().any(|m| cmdline_lower.contains(m)) {
            score = score.saturating_add(25);
        }

        // Signal 3: AI framework module or library imported via command line (+20)
        // e.g. `python -m langchain ...`, `node openai-sdk/index.js ...`
        const AI_FRAMEWORK_MODULES: &[&str] = &[
            "langchain", "langgraph", "crewai", "autogen", "pyautogen",
            "llama_index", "llamaindex", "semantic_kernel", "guidance",
            "dspy", "instructor", "openagents", "agentops",
            "hermes_cli", "tui_gateway", "slash_worker", "openclaw",
        ];
        if AI_FRAMEWORK_MODULES.iter().any(|m| cmdline_lower.contains(m)) {
            score = score.saturating_add(20);
        }

        // Signal 4: LLM provider API domain in command line (+20)
        // Processes explicitly configured to call LLM APIs are agents.
        const LLM_API_DOMAINS: &[&str] = &[
            "api.anthropic.com", "api.openai.com", "generativelanguage.googleapis.com",
            "api.cohere.com", "api.mistral.ai", "api.groq.com", "openrouter.ai",
            "api.together.xyz", "api.deepseek.com",
        ];
        if LLM_API_DOMAINS.iter().any(|d| cmdline_lower.contains(d)) {
            score = score.saturating_add(20);
        }

        // Signal 5: `--model` flag in args (+15)
        // Any process that accepts a `--model` argument is almost certainly
        // an AI agent or AI tool, regardless of its name.
        if cmdline_lower.contains("--model ") || cmdline_lower.contains("--model=") {
            score = score.saturating_add(15);
        }

        // Signal 6: Framework metadata matched (for labeling, not primary detection) (+10)
        // Generic runtimes alone are not enough; only count specific framework matches.
        const GENERIC_FRAMEWORKS: &[&str] = &["Python Agent", "Node Agent", "Docker Agent"];
        if framework.is_some() && !GENERIC_FRAMEWORKS.iter().any(|f| framework.as_deref() == Some(f)) {
            score = score.saturating_add(10);
        }

        // Signal 7: Known model provider resolved (+10)
        if model_provider.is_some() {
            score = score.saturating_add(10);
        }

        // Signal 8: Long-running process (sustained CPU use) (+5)
        if cpu_ticks > 1000.0 {
            score = score.saturating_add(5);
        }

        score.min(100)
    }

    fn detect_model_provider(&self, cmdline: &str, raw_env_vars: &[String]) -> Option<String> {
        let cmdline_lower = cmdline.to_lowercase();

        if cmdline_lower.contains("anthropic") || cmdline_lower.contains("claude") {
            Some("Anthropic".to_string())
        } else if cmdline_lower.contains("openai") || cmdline_lower.contains("gpt") {
            Some("OpenAI".to_string())
        } else if cmdline_lower.contains("gemini") || cmdline_lower.contains("google") {
            Some("Google".to_string())
        } else if cmdline_lower.contains("ollama") || cmdline_lower.contains("llama") || cmdline_lower.contains("mistral") {
            Some("Local/Ollama".to_string())
        } else if raw_env_vars.iter().any(|e| e == "ANTHROPIC_API_KEY") {
            Some("Anthropic".to_string())
        } else if raw_env_vars.iter().any(|e| e == "OPENAI_API_KEY") {
            Some("OpenAI".to_string())
        } else if raw_env_vars.iter().any(|e| e.contains("GROQ") || e.contains("TOGETHER") || e.contains("OPENROUTER")) {
            Some("Multi-provider".to_string())
        } else {
            None
        }
    }

    /// Scan active TCP connections and return a map of PID → provider name
    /// for any process that currently has an open connection to an LLM provider API.
    ///
    /// Cached for 30 seconds. LLM provider IPs are resolved once per refresh cycle
    /// so the hot path is a simple HashSet lookup, not a DNS query.
    fn refresh_llm_connections(&self) {
        let needs_refresh = {
            let cache = self.llm_conn_cache.lock().unwrap();
            cache.refreshed_at.elapsed() > Duration::from_secs(30)
        };
        if !needs_refresh {
            return;
        }

        // Step 1: resolve all LLM provider hostnames to IPs (once per refresh cycle).
        use std::net::ToSocketAddrs;
        let mut provider_ips: HashMap<String, &str> = HashMap::new();
        for (hostname, provider) in LLM_PROVIDER_HOSTS {
            if let Ok(addrs) = format!("{}:443", hostname).to_socket_addrs() {
                for addr in addrs {
                    provider_ips.insert(addr.ip().to_string(), provider);
                }
            }
        }

        // Step 2: enumerate active HTTPS connections with lsof (-F = field output).
        // p<pid>  →  n<local->remote>
        let mut pids: HashSet<u32> = HashSet::new();
        let mut providers: HashMap<u32, String> = HashMap::new();

        if let Ok(out) = std::process::Command::new("lsof")
            .args(["-n", "-P", "-i", "TCP:443", "-sTCP:ESTABLISHED", "-F", "pn"])
            .output()
        {
            let text = String::from_utf8_lossy(&out.stdout);
            let mut current_pid: Option<u32> = None;
            for line in text.lines() {
                if let Some(pid_str) = line.strip_prefix('p') {
                    current_pid = pid_str.parse().ok();
                } else if let Some(addr) = line.strip_prefix('n') {
                    if let Some(pid) = current_pid {
                        // addr: 1.2.3.4:port->5.6.7.8:443  or  [::1]:port->[::1]:443
                        if let Some(remote) = addr.split("->").nth(1) {
                            let remote_ip = remote
                                .split(':').next().unwrap_or("")
                                .trim_matches('[').trim_matches(']');
                            if let Some(&provider) = provider_ips.get(remote_ip) {
                                pids.insert(pid);
                                providers.entry(pid).or_insert_with(|| provider.to_string());
                            }
                        }
                    }
                }
            }
        }

        let mut cache = self.llm_conn_cache.lock().unwrap();
        cache.pids = pids;
        cache.providers = providers;
        cache.refreshed_at = Instant::now();
    }
}
#[cfg(target_os = "linux")]
/// Estimate a process's CPU usage as a percentage of total system uptime.
/// Uses `/proc/uptime` to get the system uptime in seconds.
/// CLK_TCK is assumed to be 100 (standard on Linux x86).
fn estimate_cpu_percentage(cpu_ticks: f64) -> f64 {
    if cpu_ticks <= 0.0 {
        return 0.0;
    }
    let uptime_path = format!("{}/uptime", crate::proc_root());
    if let Ok(uptime_str) = std::fs::read_to_string(&uptime_path) {
        // /proc/uptime format: "uptime_secs idle_secs"
        if let Some(uptime_secs_str) = uptime_str.split_whitespace().next() {
            if let Ok(uptime_secs) = uptime_secs_str.parse::<f64>() {
                let clk_tck = 100.0;
                let process_secs = cpu_ticks / clk_tck;
                if uptime_secs > 0.0 {
                    let pct = (process_secs / uptime_secs) * 100.0;
                    return pct.min(100.0);
                }
            }
        }
    }
    0.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_framework_detection() {
        let discovery = AgentDiscovery::new();

        assert_eq!(
            discovery.detect_framework("claude", "claude code run", &[]),
            Some("Claude Code".to_string())
        );

        assert_eq!(
            discovery.detect_framework("python", "crewai main.py", &[]),
            Some("CrewAI".to_string())
        );

        assert_eq!(
            discovery.detect_framework("python", "langgraph server", &vec!["LANGGRAPH".to_string()]),
            Some("LangGraph".to_string())
        );

        assert_eq!(
            discovery.detect_framework("docker", "docker run agent", &[]),
            Some("Docker Agent".to_string())
        );

        assert_eq!(
            discovery.detect_framework("python3", "python3 app.py", &[]),
            Some("Python Agent".to_string())
        );

        assert_eq!(
            discovery.detect_framework("node", "node server.js", &[]),
            Some("Node Agent".to_string())
        );
    }

    #[test]
    fn test_model_provider_detection() {
        let discovery = AgentDiscovery::new();

        assert_eq!(
            discovery.detect_model_provider("openai api call", &[]),
            Some("OpenAI".to_string())
        );

        assert_eq!(
            discovery.detect_model_provider("anthropic claude", &[]),
            Some("Anthropic".to_string())
        );

        assert_eq!(
            discovery.detect_model_provider("python app.py", &vec!["OPENAI_API_KEY".to_string()]),
            Some("OpenAI".to_string())
        );
    }

    #[test]
    fn test_filter_sensitive_env_vars() {
        let discovery = AgentDiscovery::new();

        let vars = vec![
            "OPENAI_API_KEY".to_string(),
            "PATH".to_string(),
            "ANTHROPIC_API_KEY".to_string(),
            "HOME".to_string(),
        ];
        let filtered = discovery.filter_sensitive_env_vars(&vars);
        assert_eq!(filtered.len(), 2);
        assert!(filtered.contains(&"PATH".to_string()));
        assert!(filtered.contains(&"HOME".to_string()));
    }

    #[test]
    fn test_calculate_confidence() {
        let discovery = AgentDiscovery::new();

        // High confidence: known framework + model provider + indicators
        let high = discovery.calculate_confidence(
            "claude-agent",
            "claude code run --model openai",
            &["OPENAI_API_KEY".to_string()],
            &Some("Claude Code".to_string()),
            &Some("OpenAI".to_string()),
            5000.0,
        );
        assert!(high >= 70, "Expected high confidence >= 70, got {}", high);

        // Low confidence: generic process with no indicators
        let low = discovery.calculate_confidence(
            "bash",
            "bash",
            &[] as &[String],
            &None,
            &None,
            0.0,
        );
        assert!(low <= 10, "Expected low confidence <= 10, got {}", low);
    }
}
