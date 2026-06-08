//! Thor Firewall — xtask build tool
//! بناء eBPF programs باستخدام cargo xtask
//! SPDX-License-Identifier: MIT
use std::process::Command;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(|s| s.as_str()) {
        Some("build-ebpf") => build_ebpf(),
        Some("check")      => check_all(),
        _ => {
            eprintln!("Usage: cargo xtask <build-ebpf|check>");
            std::process::exit(1);
        }
    }
}

fn build_ebpf() {
    println!("🔨 Building eBPF programs for bpfel-unknown-none target...");
    let status = Command::new("cargo")
        .args([
            "build",
            "--package", "thor-agent-ebpf",
            "--target", "bpfel-unknown-none",
            "-Z", "build-std=core",
            "--release",
        ])
        .env("CARGO_UNSTABLE_TARGET_APPLIES_TO_HOST", "false")
        .env("RUSTFLAGS", "-C link-arg=--btf")
        .status()
        .expect("Failed to run cargo build for eBPF");

    if !status.success() {
        eprintln!("❌ eBPF build failed. Make sure rustup target add bpfel-unknown-none");
        std::process::exit(1);
    }
    println!("✅ eBPF programs built successfully");
}

fn check_all() {
    let status = Command::new("cargo")
        .args(["check", "--workspace"])
        .status()
        .expect("cargo check failed");
    if !status.success() { std::process::exit(1); }
    println!("✅ All workspace checks passed");
}
