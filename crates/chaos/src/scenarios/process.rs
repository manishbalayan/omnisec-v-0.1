use std::process::{Command, Stdio, Child};
use std::time::{Duration, Instant};
use anyhow::Result;

pub struct ChaosAgent {
    pub child: Option<Child>,
    pub pid: Option<u32>,
    pub name: String,
    pub started_at: Option<Instant>,
}

impl ChaosAgent {
    pub fn new(name: &str) -> Self {
        Self {
            child: None,
            pid: None,
            name: name.to_string(),
            started_at: None,
        }
    }

    pub fn start_healthy(&mut self) -> Result<u32> {
        self.start_agent(&["healthy-loop", "--interval-secs", "1"])
    }

    pub fn start_exit_immediately(&mut self) -> Result<u32> {
        self.start_agent(&["exit-immediately"])
    }

    pub fn start_crash_after(&mut self, seconds: u64) -> Result<u32> {
        self.start_agent(&["crash-after-seconds", "--seconds", &seconds.to_string()])
    }

    pub fn start_hang(&mut self) -> Result<u32> {
        self.start_agent(&["hang-forever"])
    }

    pub fn start_cpu_consumer(&mut self, load: f64) -> Result<u32> {
        self.start_agent(&["consume-cpu", "--load", &load.to_string()])
    }

    pub fn start_memory_consumer(&mut self, mb: usize) -> Result<u32> {
        self.start_agent(&["consume-memory", "--mb", &mb.to_string()])
    }

    pub fn start_stop_responding(&mut self, after_secs: u64) -> Result<u32> {
        self.start_agent(&["stop-responding", "--after-seconds", &after_secs.to_string()])
    }

    fn start_agent(&mut self, args: &[&str]) -> Result<u32> {
        let child = Command::new("cargo")
            .args(["run", "--bin", "chaos-agent", "--"])
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;

        let pid = child.id();
        self.child = Some(child);
        self.pid = Some(pid);
        self.started_at = Some(Instant::now());

        Ok(pid)
    }

    pub fn kill(&mut self) -> Result<()> {
        if let Some(ref mut child) = self.child {
            child.kill()?;
            child.wait()?;
        }
        self.child = None;
        self.pid = None;
        Ok(())
    }

    pub fn is_alive(&mut self) -> bool {
        if let Some(ref mut child) = self.child {
            match child.try_wait() {
                Ok(Some(_)) => false,
                Ok(None) => true,
                Err(_) => false,
            }
        } else {
            false
        }
    }

    pub fn pid(&self) -> Option<u32> {
        self.pid
    }

    pub fn uptime(&self) -> Option<Duration> {
        self.started_at.map(|s| s.elapsed())
    }
}

impl Drop for ChaosAgent {
    fn drop(&mut self) {
        let _ = self.kill();
    }
}

pub fn check_process_alive(pid: u32) -> bool {
    #[cfg(target_os = "linux")]
    {
        std::path::Path::new(&format!("/proc/{}", pid)).exists()
    }

    #[cfg(target_os = "macos")]
    {
        Command::new("kill")
            .args(["-0", &pid.to_string()])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        false
    }
}

pub fn kill_process(pid: u32) -> Result<()> {
    Command::new("kill")
        .args(["-9", &pid.to_string()])
        .output()?;
    Ok(())
}
