use anyhow::Result;
use serde::{Deserialize, Serialize};

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
                name: "OpenAI Agents SDK".to_string(),
                process_patterns: vec!["openai".to_string(), "agents".to_string()],
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

        for entry in fs::read_dir("/proc")? {
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

        let comm = fs::read_to_string(format!("/proc/{}/comm", pid)).ok()?;
        let cmdline = fs::read_to_string(format!("/proc/{}/cmdline", pid)).ok()?;
        let stat = fs::read_to_string(format!("/proc/{}/stat", pid)).ok()?;

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
        let model_provider = self.detect_model_provider(&cmdline, &env_vars);

        let confidence = self.calculate_confidence(&comm, &cmdline, &env_vars, &framework, &model_provider, cpu_ticks);

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

        let output = Command::new("ps")
            .args(["-axo", "pid,ppid,comm,args"])
            .output()?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut agents = Vec::new();

        for line in stdout.lines().skip(1) {
            let parts: Vec<&str> = line.splitn(4, char::is_whitespace).collect();
            if parts.len() >= 3 {
                if let (Ok(pid), Ok(ppid)) = (parts[0].parse::<u32>(), parts[1].parse::<u32>()) {
                    let comm = parts[2].to_string();
                    let cmdline = if parts.len() > 3 { parts[3].to_string() } else { comm.clone() };

                    let env_vars = self.get_env_vars(pid);
                    let filtered_env_vars = self.filter_sensitive_env_vars(&env_vars);
                    let framework = self.detect_framework(&comm, &cmdline, &filtered_env_vars);
                    let model_provider = self.detect_model_provider(&cmdline, &filtered_env_vars);
                    let confidence = self.calculate_confidence(&comm, &cmdline, &filtered_env_vars, &framework, &model_provider, 0.0);

                    agents.push(DiscoveredAgent {
                        pid,
                        ppid: Some(ppid),
                        name: comm,
                        command: cmdline,
                        framework,
                        model_provider,
                        memory_mb: None,
                        cpu_percent: None,
                        status: AgentStatus::Running,
                        env_vars: filtered_env_vars,
                        listening_ports: vec![],
                        confidence,
                    });
                }
            }
        }

        Ok(agents)
    }

    fn get_env_vars(&self, pid: u32) -> Vec<String> {
        #[cfg(target_os = "linux")]
        {
            return self._get_env_vars_linux(pid);
        }
        // macOS and other platforms: env vars not available via ps
        #[allow(unused_variables)]
        let _ = pid;
        vec![]
    }

    #[cfg(target_os = "linux")]
    fn _get_env_vars_linux(&self, pid: u32) -> Vec<String> {
        use std::fs;

        let env_path = format!("/proc/{}/environ", pid);
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

        let mut ports = Vec::new();
        let tcp_path = format!("/proc/{}/net/tcp", pid);
        let udp_path = format!("/proc/{}/net/udp", pid);

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
    fn calculate_confidence(
        &self,
        comm: &str,
        cmdline: &str,
        env_vars: &[String],
        framework: &Option<String>,
        model_provider: &Option<String>,
        cpu_ticks: f64,
    ) -> u8 {
        let mut score: u8 = 0;

        // Signal 1: Process name contains agent-related keywords (+25)
        let comm_lower = comm.to_lowercase();
        let agent_keywords = ["agent", "bot", "assistant", "ai-", "llm", "model", "crew"];
        if agent_keywords.iter().any(|k| comm_lower.contains(k)) {
            score = score.saturating_add(25);
        }

        // Signal 2: Known AI model API indicators in command line or env (+25)
        let cmdline_lower = cmdline.to_lowercase();
        let model_indicators = ["openai", "anthropic", "claude", "gpt-", "gemini", "llama", "mistral"];
        if model_indicators.iter().any(|k| cmdline_lower.contains(k)) {
            score = score.saturating_add(25);
        }

        // Signal 3: Known specific framework match (+20)
        // Generic runtimes (Python, Node, Docker) are not a strong signal.
        if framework.is_some()
            && framework.as_deref() != Some("Python Agent")
            && framework.as_deref() != Some("Node Agent")
            && framework.as_deref() != Some("Docker Agent")
        {
            score = score.saturating_add(20);
        }

        // Signal 4: Known model provider (+15)
        if model_provider.is_some() {
            score = score.saturating_add(15);
        }

        // Signal 5: AI-related env vars in the (filtered) environment (+15)
        if env_vars.iter().any(|v| {
            let upper = v.to_uppercase();
            upper.contains("OPENAI") || upper.contains("ANTHROPIC") || upper.contains("VIRTUAL_ENV")
        }) {
            score = score.saturating_add(15);
        }

        // Signal 6: Long-running process (high cumulative CPU ticks) (+10)
        if cpu_ticks > 1000.0 {
            score = score.saturating_add(10);
        }

        // Signal 7: Generic runtime with API keys — might still be agent (+5)
        let is_generic_runtime = comm_lower.contains("python") || comm_lower.contains("node");
        if is_generic_runtime && framework.is_some() {
            score = score.saturating_add(5);
        }

        score.min(100)
    }

    fn detect_model_provider(&self, cmdline: &str, env_vars: &[String]) -> Option<String> {
        let cmdline_lower = cmdline.to_lowercase();

        if cmdline_lower.contains("openai") || cmdline_lower.contains("gpt") {
            Some("OpenAI".to_string())
        } else if cmdline_lower.contains("anthropic") || cmdline_lower.contains("claude") {
            Some("Anthropic".to_string())
        } else if cmdline_lower.contains("gemini") || cmdline_lower.contains("google") {
            Some("Google".to_string())
        } else if env_vars.iter().any(|e| e == "OPENAI_API_KEY") {
            Some("OpenAI".to_string())
        } else if env_vars.iter().any(|e| e == "ANTHROPIC_API_KEY") {
            Some("Anthropic".to_string())
        } else {
            None
        }
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
    if let Ok(uptime_str) = std::fs::read_to_string("/proc/uptime") {
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
