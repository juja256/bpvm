fn main() {
    // Make link.ld visible to `-Tlink.ld` (see .cargo/config.toml) for every binary that
    // depends on this crate: link search paths propagate to dependents.
    println!("cargo:rustc-link-search={}", std::env::var("CARGO_MANIFEST_DIR").unwrap());
    println!("cargo:rerun-if-changed=link.ld");
}
