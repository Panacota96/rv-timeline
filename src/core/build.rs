// Embeds the exact dependency versions from Cargo.lock so every run's
// environment.json records them (reproducibility for court).
use std::{env, fs, path::PathBuf};

fn main() {
    let lock = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join("../../Cargo.lock");
    println!("cargo:rerun-if-changed={}", lock.display());
    let text = fs::read_to_string(&lock).unwrap_or_default();
    let mut deps = Vec::new();
    let mut name: Option<String> = None;
    for line in text.lines() {
        if let Some(v) = line.strip_prefix("name = \"") {
            name = Some(v.trim_end_matches('"').to_string());
        } else if let (Some(v), Some(n)) = (line.strip_prefix("version = \""), name.take()) {
            deps.push(format!("{}@{}", n, v.trim_end_matches('"')));
        }
    }
    println!("cargo:rustc-env=RV_DEPENDENCIES={}", deps.join(","));

    // Product version: version.txt is the single source of truth (release-please bumps it).
    let vfile = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join("../../version.txt");
    println!("cargo:rerun-if-changed={}", vfile.display());
    let product = fs::read_to_string(&vfile)
        .map(|v| v.trim().to_string())
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| env::var("CARGO_PKG_VERSION").unwrap_or_default());
    println!("cargo:rustc-env=RV_VERSION={product}");

    let rustc = env::var("RUSTC").unwrap_or_else(|_| "rustc".into());
    let version = std::process::Command::new(rustc)
        .arg("--version")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .unwrap_or_default();
    println!("cargo:rustc-env=RV_RUSTC={}", version.trim());
    println!(
        "cargo:rustc-env=RV_TARGET={}",
        env::var("TARGET").unwrap_or_default()
    );
}
