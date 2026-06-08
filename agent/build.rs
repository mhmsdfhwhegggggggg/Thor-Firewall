//! Thor Agent — Build Script
//! تجميع proto files باستخدام tonic-build (Tonic gRPC)

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // compile proto → Rust (Tonic + Prost)
    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .out_dir("src/grpc/generated")
        .compile(
            &["proto/thor.proto"],
            &["proto/"],
        )?;
    
    println!("cargo:rerun-if-changed=proto/thor.proto");
    println!("cargo:rerun-if-changed=build.rs");
    Ok(())
}
