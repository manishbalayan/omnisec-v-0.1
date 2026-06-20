//! # OMNISEC eBPF Build Script
//!
//! Automatically compiles the BPF kernel programs (`omnisec-ebpf-bpf`) and
//! embeds the resulting ELF bytecode into the userspace binary at build time.
//!
//! This runs ONLY on Linux (the BPF target is `bpfel-unknown-none`).
//! On macOS, the build script is a no-op and the code falls back to `/proc` monitoring.
//!
//! Prerequisites:
//!   - `bpf-linker` must be installed (`cargo install bpf-linker`)
//!   - `bpfel-unknown-none` target must be installed (`rustup target add bpfel-unknown-none`)

use std::path::PathBuf;
use std::process::Command;

fn main() {
    // Only compile BPF programs on Linux.
    // On macOS, the userspace code uses `include_bytes_aligned!` which falls back
    // to an empty Vec. The runtime fallback to /proc monitoring handles this case.
    #[cfg(target_os = "linux")]
    build_bpf_programs();

    #[cfg(not(target_os = "linux"))]
    println!("cargo:warning=Not on Linux — eBPF programs will not be compiled. Using /proc fallback.");
}

/// Compile the BPF kernel programs for the Linux kernel.
#[cfg(target_os = "linux")]
fn build_bpf_programs() {
    // Paths
    let workspace_root = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap())
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();
    let bpf_crate = workspace_root.join("crates").join("ebpf-bpf");
    let target_dir = workspace_root.join("target");
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    // Verify bpf-linker is available
    let linker_check = Command::new("which")
        .arg("bpf-linker")
        .output()
        .ok()
        .and_then(|o| if o.status.success() { Some(()) } else { None });

    if linker_check.is_none() {
        // Try cargo binstall or direct check
        let cargo_check = Command::new("cargo")
            .args(["install", "--list"])
            .output()
            .ok()
            .and_then(|o| {
                let stdout = String::from_utf8_lossy(&o.stdout);
                if stdout.contains("bpf-linker") { Some(()) } else { None }
            });

        if cargo_check.is_none() {
            println!("cargo:warning=bpf-linker not found. Install it with: cargo install bpf-linker");
            println!("cargo:warning=eBPF programs will NOT be compiled. Falling back to /proc monitoring.");
            return;
        }
    }

    // Check if the BPF target is installed
    let target_check = Command::new("rustup")
        .args(["target", "list", "--installed"])
        .output()
        .ok()
        .and_then(|o| {
            let stdout = String::from_utf8_lossy(&o.stdout);
            if stdout.contains("bpfel-unknown-none") { Some(()) } else { None }
        });

    if target_check.is_none() {
        println!("cargo:warning=bpfel-unknown-none target not installed. Install it with: rustup target add bpfel-unknown-none");
        println!("cargo:warning=eBPF programs will NOT be compiled. Falling back to /proc monitoring.");
        return;
    }

    // Build the BPF programs (always release-optimized for kernel performance)
    let status = Command::new("cargo")
        .args([
            "build",
            "--target", "bpfel-unknown-none",
            "-p", "omnisec-ebpf-bpf",
            "--release", // BPF programs should always be built in release mode
        ])
        .env("CARGO_TARGET_DIR", &target_dir)
        .current_dir(&workspace_root)
        .status()
        .expect("Failed to build eBPF programs");

    if !status.success() {
        println!("cargo:warning=eBPF program compilation failed. Falling back to /proc monitoring.");
        return;
    }

    // Locate the compiled BPF ELF
    let bpf_elf = target_dir
        .join("bpfel-unknown-none")
        .join("release")
        .join("omnisec-ebpf-bpf");

    if !bpf_elf.exists() {
        println!(
            "cargo:warning=BPF ELF not found at {}. Falling back to /proc monitoring.",
            bpf_elf.display()
        );
        return;
    }

    // Copy to OUT_DIR so the userspace code can include it
    let out_path = out_dir.join("omnisec-ebpf-bpf");
    std::fs::copy(&bpf_elf, &out_path).expect("Failed to copy BPF ELF to OUT_DIR");

    let size = std::fs::metadata(&out_path).map(|m| m.len()).unwrap_or(0);
    println!("cargo:warning=eBPF programs compiled successfully ({} bytes at {})", size, out_path.display());

    // Set rerun-if-changed for incremental builds
    println!("cargo:rerun-if-changed={}", bpf_crate.join("src").display());
    println!("cargo:rerun-if-changed={}", bpf_crate.join("Cargo.toml").display());
    println!("cargo:rerun-if-changed={}", workspace_root.join("crates").join("ebpf-common").join("src").display());
}

