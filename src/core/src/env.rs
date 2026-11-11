//! `environment.json`: what ran, where and with which exact dependency versions.
//! Lets a second examiner reproduce the run (ISO/IEC 27037 §7: documented, repeatable process).

use serde_json::{Value, json};

pub fn hostname() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .ok()
        .or_else(|| {
            std::fs::read_to_string("/etc/hostname")
                .ok()
                .map(|s| s.trim().to_string())
        })
        .unwrap_or_else(|| "unknown".into())
}

pub fn os_user() -> String {
    std::env::var("USERNAME")
        .or_else(|_| std::env::var("USER"))
        .unwrap_or_else(|_| "unknown".into())
}

pub fn dependencies() -> Vec<String> {
    env!("RV_DEPENDENCIES")
        .split(',')
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect()
}

pub fn describe(tool: &str, version: &str, frontend: &str, args: &[String]) -> Value {
    json!({
        "tool": {"name": tool, "version": version, "frontend": frontend, "rustc": env!("RV_RUSTC"), "target": env!("RV_TARGET")},
        "os": {"family": std::env::consts::FAMILY, "name": std::env::consts::OS, "arch": std::env::consts::ARCH},
        "host": hostname(),
        "os_user": os_user(),
        "working_directory": std::env::current_dir().map(|p| p.display().to_string()).unwrap_or_default(),
        "command_line": args,
        "recorded_utc": crate::time::utc_now(),
        "dependencies": dependencies(),
    })
}
