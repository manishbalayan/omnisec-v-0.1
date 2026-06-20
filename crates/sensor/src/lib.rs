use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessEvent {
    pub pid: u32,
    pub ppid: u32,
    pub comm: String,
    pub event_type: ProcessEventType,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProcessEventType {
    Exec,
    Exit,
    Fork,
    Clone,
}

pub struct Sensor {
    running: bool,
}

impl Default for Sensor {
    fn default() -> Self {
        Self::new()
    }
}

impl Sensor {
    pub fn new() -> Self {
        Self { running: false }
    }

    pub async fn start(&mut self) -> Result<()> {
        tracing::info!("Starting sensor");
        self.running = true;
        
        loop {
            if !self.running {
                break;
            }
            
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
        
        Ok(())
    }

    pub fn stop(&mut self) {
        self.running = false;
    }

    pub fn is_running(&self) -> bool {
        self.running
    }
}
