use std::error::Error;

// rootd.proto lives here, in the repo that owns the daemon, and the app symlinks it
// into its own proto dir - the same arrangement appcontrol.proto has between the app
// and vk-turn-proxy. One file, so the two sides cannot drift apart.
fn main() -> Result<(), Box<dyn Error>> {
    let proto_dir = "../proto";
    let proto = format!("{proto_dir}/rootd.proto");
    println!("cargo:rerun-if-changed={proto}");

    prost_build::Config::new()
        .protoc_executable(protoc_bin_vendored::protoc_bin_path()?)
        .compile_protos(&[proto], &[proto_dir])?;
    Ok(())
}
