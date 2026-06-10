//! Thor Firewall — eBPF Build Orchestrator (xtask)
//!
//! يجمع eBPF programs باستخدام clang + llvm-strip
//! ويضع النتيجة في OUT_DIR حيث يقرأها aya في `maps.rs`
//!
//! الاستخدام:
//!   cargo xtask build-ebpf             # compile for current arch
//!   cargo xtask build-ebpf --release   # with optimizations
//!   cargo xtask test-ebpf              # build + run in BPF verifier (kfunc)
//!
//! SPDX-License-Identifier: MIT

use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(|s| s.as_str()).unwrap_or("build-ebpf");
    let release = args.contains(&"--release".to_string());

    match cmd {
        "build-ebpf" => build_ebpf(release),
        "check-deps"  => check_deps(),
        "clean"       => clean_ebpf(),
        "help" | _    => print_help(),
    }
}

fn workspace_root() -> PathBuf {
    // Walk up from xtask to find Cargo.toml with [workspace]
    let mut dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR")
        .unwrap_or_else(|_| ".".to_string()));
    loop {
        let toml = dir.join("Cargo.toml");
        if toml.exists() {
            let content = std::fs::read_to_string(&toml).unwrap_or_default();
            if content.contains("[workspace]") {
                return dir;
            }
        }
        if !dir.pop() { break; }
    }
    PathBuf::from(".")
}

fn ebpf_src_dir() -> PathBuf {
    workspace_root().join("agent-core").join("ebpf")
}

fn ebpf_out_dir() -> PathBuf {
    workspace_root().join("target").join("ebpf")
}

fn build_ebpf(release: bool) {
    check_deps();

    let src  = ebpf_src_dir();
    let out  = ebpf_out_dir();
    std::fs::create_dir_all(&out).expect("Failed to create ebpf out dir");

    // BPF source files to compile
    let bpf_sources = vec![
        ("thor_xdp.bpf.c",          "thor_xdp"),
        ("thor_integrated.bpf.c",    "thor_integrated"),
    ];

    let include_dirs = vec![
        src.join("include"),
        src.join("vmlinux"),
        workspace_root().join("vendor").join("libbpf").join("include"),
        workspace_root().join("vendor").join("libbpf").join("include").join("uapi"),
    ];

    let mut all_ok = true;

    for (src_file, out_name) in &bpf_sources {
        let src_path = src.join(src_file);
        if !src_path.exists() {
            eprintln!("WARNING: {} not found — skipping", src_path.display());
            continue;
        }

        let obj_path = out.join(format!("{}.o", out_name));
        let skel_path = out.join(format!("{}", out_name));

        println!("Compiling {} → {}", src_file, obj_path.display());

        // clang -target bpf compile
        let mut cmd = Command::new("clang");
        cmd.args([
            "-target", "bpf",
            "-O2",
            "-g",                    // BTF debug info
            "-Wall", "-Wno-unused-value", "-Wno-pointer-sign",
            "-Wno-compare-distinct-pointer-types",
        ]);

        if release {
            cmd.args(["-O3", "-DNDEBUG"]);
        }

        for inc in &include_dirs {
            if inc.exists() {
                cmd.arg("-I").arg(inc);
            }
        }

        cmd.arg("-c").arg(&src_path).arg("-o").arg(&obj_path);

        match run_command(&mut cmd) {
            Ok(status) if status.success() => {
                println!("  ✓ Compiled: {}", obj_path.display());

                // Strip debug symbols for production (keep BTF)
                let stripped = out.join(format!("{}.stripped.o", out_name));
                let mut strip_cmd = Command::new("llvm-strip");
                strip_cmd.args(["-g"]);
                strip_cmd.arg(&obj_path).arg("-o").arg(&stripped);
                if let Ok(s) = run_command(&mut strip_cmd) {
                    if s.success() {
                        std::fs::rename(&stripped, &skel_path)
                            .or_else(|_| std::fs::copy(&obj_path, &skel_path).map(|_| ()))
                            .expect("Failed to write final eBPF object");
                    } else {
                        std::fs::copy(&obj_path, &skel_path).expect("copy failed");
                    }
                } else {
                    // llvm-strip not found — use unstripped
                    std::fs::copy(&obj_path, &skel_path).expect("copy failed");
                }
                println!("  ✓ Final:    {}", skel_path.display());
            }
            Ok(status) => {
                eprintln!("  ✗ clang exited with: {}", status);
                all_ok = false;
            }
            Err(e) => {
                eprintln!("  ✗ clang failed: {}", e);
                all_ok = false;
            }
        }
    }

    if all_ok {
        println!("\n✅ eBPF build complete: {}", out.display());
        println!("   Set OUT_DIR={} when building the agent", out.display());
    } else {
        eprintln!("\n❌ Some eBPF programs failed to compile");
        std::process::exit(1);
    }
}

fn check_deps() {
    let required = vec!["clang", "llvm-strip"];
    let mut missing = vec![];

    for dep in &required {
        let status = Command::new(dep).arg("--version").output();
        match status {
            Ok(out) if out.status.success() => {
                let ver = String::from_utf8_lossy(&out.stdout);
                let ver_line = ver.lines().next().unwrap_or("?");
                println!("  ✓ {}: {}", dep, ver_line);
            }
            _ => {
                eprintln!("  ✗ Missing: {}", dep);
                missing.push(*dep);
            }
        }
    }

    if !missing.is_empty() {
        eprintln!("\nInstall missing dependencies:");
        eprintln!("  Ubuntu/Debian: apt-get install clang llvm");
        eprintln!("  Fedora/RHEL:   dnf install clang llvm");
        eprintln!("  NixOS:         nix-env -iA nixpkgs.clang nixpkgs.llvm");
        eprintln!("\nOr use Docker builder:");
        eprintln!("  docker build -f Dockerfile.ebpf -t thor-ebpf-builder .");
        eprintln!("  docker run --rm -v $(pwd):/work thor-ebpf-builder cargo xtask build-ebpf");
    }
}

fn clean_ebpf() {
    let out = ebpf_out_dir();
    if out.exists() {
        std::fs::remove_dir_all(&out).expect("clean failed");
        println!("Cleaned: {}", out.display());
    }
}

fn run_command(cmd: &mut Command) -> Result<ExitStatus, std::io::Error> {
    println!("  $ {:?}", cmd);
    cmd.status()
}

fn print_help() {
    println!("Thor eBPF Build Orchestrator");
    println!();
    println!("USAGE:");
    println!("  cargo xtask <COMMAND>");
    println!();
    println!("COMMANDS:");
    println!("  build-ebpf [--release]   Compile eBPF XDP programs");
    println!("  check-deps               Check clang/llvm availability");
    println!("  clean                    Remove compiled eBPF objects");
    println!("  help                     Show this help");
}
