use protobuf_codegen::Codegen;
use protoc_bin_vendored::protoc_bin_path;

fn main() {
    // Use this in build.rs
    Codegen::new()
        // Use `protoc` parser, optional.
        .protoc()
        // Use `protoc-bin-vendored` bundled protoc command, optional.
        .protoc_path(&protoc_bin_path().unwrap())
        // All inputs and imports from the inputs must reside in `includes` directories.
        .includes(&["."])
        // Inputs must reside in some of include paths.
        .input("attestation.proto")
        // Specify output directory relative to Cargo output directory.
        .cargo_out_dir("protos")
        .run_from_script();
}
