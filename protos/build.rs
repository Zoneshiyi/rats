use protoc_bin_vendored::protoc_bin_path;

fn main() {
    unsafe {
        std::env::set_var("PROTOC", protoc_bin_path().unwrap());
    }
    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(&["attestation.proto"], &["."])
        .expect("compile protos");
}
