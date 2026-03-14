use protobuf_codegen::Codegen;
use protoc_bin_vendored::protoc_bin_path;
use std::fs;
use std::path::PathBuf;

fn main() {
    Codegen::new()
        .protoc()
        .protoc_path(&protoc_bin_path().unwrap())
        .includes(&["."])
        .input("attestation.proto")
        .cargo_out_dir("protos")
        .run_from_script();

    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let generated_path = out_dir.join("protos").join("attestation.rs");
    let sanitized_path = out_dir.join("protos").join("attestation_sanitized.rs");
    let generated = fs::read_to_string(&generated_path).unwrap();
    let sanitized = generated
        .lines()
        .filter(|line| !line.starts_with("#!") && !line.starts_with("//!"))
        .collect::<Vec<_>>()
        .join("\n");
    fs::write(&sanitized_path, format!("{sanitized}\n")).unwrap();
}
