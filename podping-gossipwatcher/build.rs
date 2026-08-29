// Expose the locked iroh dependency version so nodes can announce it to the mesh.
fn main() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let lock_path = std::path::Path::new(&manifest_dir).join("../Cargo.lock");
    println!("cargo:rerun-if-changed={}", lock_path.display());
    let lock = std::fs::read_to_string(&lock_path).expect("read workspace Cargo.lock");
    let mut in_iroh = false;
    for line in lock.lines() {
        if line.trim() == "name = \"iroh\"" {
            in_iroh = true;
        } else if in_iroh {
            if let Some(v) = line.trim().strip_prefix("version = ") {
                println!("cargo:rustc-env=IROH_VERSION={}", v.trim_matches('"'));
                return;
            }
            in_iroh = false;
        }
    }
    panic!("iroh package not found in Cargo.lock");
}
