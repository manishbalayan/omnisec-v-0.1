use clap::{Parser, Subcommand};
use std::time::Duration;
use tracing::info;

#[derive(Parser)]
#[command(name = "chaos-agent")]
#[command(about = "Test agent for chaos engineering validation")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    ExitImmediately,
    CrashAfterSeconds {
        #[arg(short, long, default_value = "5")]
        seconds: u64,
    },
    HangForever,
    ConsumeCpu {
        #[arg(short, long, default_value = "0.8")]
        load: f64,
    },
    ConsumeMemory {
        #[arg(short, long, default_value = "100")]
        mb: usize,
    },
    StopResponding {
        #[arg(short, long, default_value = "10")]
        after_seconds: u64,
    },
    HealthyLoop {
        #[arg(short, long, default_value = "1")]
        interval_secs: u64,
    },
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "chaos_agent=info".into()),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::ExitImmediately => {
            info!("Exiting immediately as requested");
            std::process::exit(0);
        }
        Commands::CrashAfterSeconds { seconds } => {
            info!("Running for {} seconds before crashing", seconds);
            tokio::time::sleep(Duration::from_secs(seconds)).await;
            info!("Crashing now!");
            std::process::exit(1);
        }
        Commands::HangForever => {
            info!("Hanging forever (blocking on infinite sleep)");
            loop {
                tokio::time::sleep(Duration::from_secs(3600)).await;
            }
        }
        Commands::ConsumeCpu { load } => {
            info!("Consuming CPU at load={}", load);
            let work_ms = (load * 100.0) as u64;
            loop {
                let start = std::time::Instant::now();
                while start.elapsed().as_millis() < work_ms as u128 {
                    std::hint::black_box(1 + 1);
                }
                let sleep_ms = 100 - work_ms;
                tokio::time::sleep(Duration::from_millis(sleep_ms)).await;
            }
        }
        Commands::ConsumeMemory { mb } => {
            info!("Allocating {} MB of memory", mb);
            let mut blocks: Vec<Vec<u8>> = Vec::new();
            let chunk_size = 1024 * 1024;
            for _ in 0..mb {
                blocks.push(vec![0xAB; chunk_size]);
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            info!("Allocated {} MB, holding", mb);
            loop {
                tokio::time::sleep(Duration::from_secs(60)).await;
            }
        }
        Commands::StopResponding { after_seconds } => {
            info!("Will stop responding after {} seconds", after_seconds);
            tokio::time::sleep(Duration::from_secs(after_seconds)).await;
            info!("Stopping response (blocking thread forever)");
            std::thread::park();
        }
        Commands::HealthyLoop { interval_secs } => {
            info!("Healthy loop running, interval={}s", interval_secs);
            loop {
                info!("heartbeat pid={}", std::process::id());
                tokio::time::sleep(Duration::from_secs(interval_secs)).await;
            }
        }
    }
}
