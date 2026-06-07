// Thor Firewall — build.rs
// يولّد كود Rust من ملف proto باستخدام tonic-build
// يجب أن يكتمل قبل تجميع أي crate تعتمد على gRPC

use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // مسار proto
    let proto_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("agent")
        .join("proto");

    // في مستودع monorepo، proto يكون في نفس مجلد الـ agent
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let proto_dir = manifest.join("proto");
    let proto_file = proto_dir.join("thor.proto");

    // أعلم Cargo بمراقبة الملف
    println!("cargo:rerun-if-changed={}", proto_file.display());
    println!("cargo:rerun-if-changed=proto/");

    tonic_build::configure()
        // تفعيل serde على جميع الأنواع المولّدة
        .type_attribute(".", "#[derive(serde::Serialize, serde::Deserialize)]")
        // تفعيل Clone على Response types
        .type_attribute(".", "#[derive(Clone)]")
        // مسار الإخراج (cargo يضعه في $OUT_DIR تلقائياً)
        .build_server(true)
        .build_client(true)
        // تفعيل reflection للـ grpcurl / grpcui
        .file_descriptor_set_path(
            PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("thor_descriptor.bin")
        )
        .compile_protos(&[proto_file], &[proto_dir])?;

    Ok(())
}
