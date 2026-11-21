//! Release check: is a newer release of a Rakvor tool published? Optional, notify only, shared byte-identical by
//! every Rakvor tool (and the forge template).
//!
//! ```text
//! GET https://github.com/Panacota96/<tool>/releases/latest      (no redirect followed, 5 s, User-Agent rv-<tool>/<ver>)
//!   └─ 302 Location: …/<tool>/releases/tag/v<X.Y.Z> ──► latest X.Y.Z ──► compare with the running version
//!        ├─ newer   ──► Check::Available { latest, url }   (the GUI shows a banner, `update-check` exits 3)
//!        ├─ same/older (a development build) ──► Check::UpToDate
//!        └─ anything else (offline, timeout, no release, rate limit) ──► Check::Failed { reason }: never blocking
//! ```
//!
//! - **When:** the GUI checks once at start-up, in the background; the CLI only through `update-check` (a run, a
//!   verification or any other command never contacts the network for it). RV Hub checks every tool it lists.
//! - **What is sent:** one HTTPS GET of the public release page, with `User-Agent: rv-<tool>/<version>` and no
//!   other header, cookie or parameter: nothing about the case, the evidence, the examiner or the machine. The check
//!   is not part of a run and is not written to any audit log.
//! - **What it does:** it reports the newer version and its release page. It never downloads or installs anything;
//!   the examiner updates and verifies the signed release (SHA256SUMS, Authenticode chain to the Rakvor root).
//! - **Off switch:** `RV_NO_UPDATE_CHECK=1` (any value but empty or `0`), or the file [`off_file`]
//!   (`%APPDATA%\Rakvor\update-check-off`, which RV Hub's setting writes) turns it off for every Rakvor tool.

use serde::Serialize;
use std::path::PathBuf;
use std::time::Duration;

/// The GitHub account that publishes the Rakvor releases.
pub const OWNER: &str = "Panacota96";
/// Environment variable that turns the check off.
pub const ENV_OFF: &str = "RV_NO_UPDATE_CHECK";
/// Name of the file that turns the check off for every Rakvor tool (in [`config_dir`]).
pub const OFF_FILE: &str = "update-check-off";
/// Longest wait for the release page.
pub const TIMEOUT: Duration = Duration::from_secs(5);
/// Schema of `update-check --json`.
pub const SCHEMA: &str = "rakvor.update-check/1";

/// The result of one check.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Check {
    /// A newer release is published.
    Available {
        current: String,
        latest: String,
        url: String,
    },
    /// The running version is the latest release (or newer: a development build).
    UpToDate { current: String, latest: String },
    /// Turned off ([`ENV_OFF`] or [`off_file`]): nothing was contacted.
    Disabled { current: String },
    /// The check could not be made (offline, timeout, no release yet, unexpected answer).
    Failed { current: String, reason: String },
}

impl Check {
    /// `available`, `up_to_date`, `disabled` or `failed`.
    pub fn status(&self) -> &'static str {
        match self {
            Check::Available { .. } => "available",
            Check::UpToDate { .. } => "up_to_date",
            Check::Disabled { .. } => "disabled",
            Check::Failed { .. } => "failed",
        }
    }

    /// One line for the console or a banner, in English.
    pub fn line(&self, tool: &str) -> String {
        match self {
            Check::Available {
                current,
                latest,
                url,
            } => format!("{tool} {latest} is available (this is {current}): {url}"),
            Check::UpToDate { current, .. } => format!("{tool} {current} is the latest release"),
            Check::Disabled { current } => {
                format!("{tool} {current}: release check turned off ({ENV_OFF} or {OFF_FILE})")
            }
            Check::Failed { current, reason } => {
                format!("{tool} {current}: could not check for a newer release ({reason})")
            }
        }
    }
}

/// The folder of the suite-wide settings: `%APPDATA%\Rakvor` on Windows, `$XDG_CONFIG_HOME/rakvor` (else
/// `~/.config/rakvor`) elsewhere. None when the variables are not set.
pub fn config_dir() -> Option<PathBuf> {
    if cfg!(windows) {
        std::env::var_os("APPDATA")
            .filter(|v| !v.is_empty())
            .map(|a| PathBuf::from(a).join("Rakvor"))
    } else {
        std::env::var_os("XDG_CONFIG_HOME")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .or_else(|| {
                std::env::var_os("HOME")
                    .filter(|v| !v.is_empty())
                    .map(|h| PathBuf::from(h).join(".config"))
            })
            .map(|c| c.join("rakvor"))
    }
}

/// The file whose presence turns the check off for every Rakvor tool.
pub fn off_file() -> Option<PathBuf> {
    config_dir().map(|d| d.join(OFF_FILE))
}

/// True when the value of [`ENV_OFF`] turns the check off (set, not empty, not `0`).
pub fn env_says_off(value: Option<&str>) -> bool {
    value.is_some_and(|v| !v.trim().is_empty() && v.trim() != "0")
}

/// True when the check is turned off (environment variable or [`off_file`]).
pub fn disabled() -> bool {
    env_says_off(std::env::var(ENV_OFF).ok().as_deref()) || off_file().is_some_and(|f| f.is_file())
}

/// Turns the suite-wide off switch on (`off = true`: creates [`off_file`]) or off (removes it).
pub fn set_off(off: bool) -> Result<(), String> {
    let f = off_file().ok_or("no settings folder (APPDATA / HOME not set)")?;
    if off {
        if let Some(d) = f.parent() {
            std::fs::create_dir_all(d).map_err(|e| format!("{}: {e}", d.display()))?;
        }
        std::fs::write(
            &f,
            b"The Rakvor tools do not check for new releases while this file exists.\n",
        )
        .map_err(|e| format!("{}: {e}", f.display()))
    } else if f.exists() {
        std::fs::remove_file(&f).map_err(|e| format!("{}: {e}", f.display()))
    } else {
        Ok(())
    }
}

/// The public page of a tool's latest release.
pub fn latest_page(tool: &str) -> String {
    format!("https://github.com/{OWNER}/{tool}/releases/latest")
}

/// The page of one release.
pub fn release_page(tool: &str, version: &str) -> String {
    format!("https://github.com/{OWNER}/{tool}/releases/tag/v{version}")
}

/// `X.Y.Z` (an optional leading `v`, no pre-release or build part) as numbers.
pub fn version_triple(v: &str) -> Option<(u64, u64, u64)> {
    let v = v.trim();
    let v = v.strip_prefix('v').unwrap_or(v);
    let mut it = v.split('.');
    let mut part = || -> Option<u64> {
        let p = it.next()?;
        if p.is_empty() || p.len() > 9 || !p.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        p.parse().ok()
    };
    let t = (part()?, part()?, part()?);
    it.next().is_none().then_some(t)
}

/// The version a `Location` header of the latest-release redirect names: `…/<OWNER>/<tool>/releases/tag/v<X.Y.Z>`
/// (absolute or relative). None for any other target (GitHub sends `…/releases` when nothing is released).
pub fn version_from_location(location: &str, tool: &str) -> Option<String> {
    let path = location
        .strip_prefix("https://github.com")
        .unwrap_or(location);
    let tag = path.strip_prefix(&format!("/{OWNER}/{tool}/releases/tag/"))?;
    let (a, b, c) = version_triple(tag)?;
    Some(format!("{a}.{b}.{c}"))
}

/// Compares the running version with the latest release.
pub fn compare(current: &str, latest: &str, tool: &str) -> Check {
    match (version_triple(current), version_triple(latest)) {
        (Some(c), Some(l)) if l > c => Check::Available {
            current: current.to_string(),
            latest: latest.to_string(),
            url: release_page(tool, latest),
        },
        (Some(_), Some(_)) => Check::UpToDate {
            current: current.to_string(),
            latest: latest.to_string(),
        },
        _ => Check::Failed {
            current: current.to_string(),
            reason: format!("cannot compare versions {current:?} and {latest:?}"),
        },
    }
}

/// True for a Rakvor tool name (`rv-` then lowercase letters, digits and inner hyphens: `rv-hub`, `rv-whatsapp-rsmf`),
/// the only names put into the release-page URL.
pub fn is_tool_name(tool: &str) -> bool {
    tool.strip_prefix("rv-").is_some_and(|rest| {
        !rest.is_empty()
            && !rest.starts_with('-')
            && !rest.ends_with('-')
            && !rest.contains("--")
            && rest
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    })
}

/// The latest released version of `tool`, from its latest-release redirect. `agent` is the User-Agent (`rv-<tool>/
/// <version>` of the tool that asks).
pub fn latest_version(tool: &str, agent: &str) -> Result<String, String> {
    if !is_tool_name(tool) {
        return Err(format!("not a Rakvor tool name: {tool:?}"));
    }
    let http: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(TIMEOUT))
        .max_redirects(0)
        .max_redirects_will_error(false)
        .http_status_as_error(false)
        .user_agent(agent)
        .build()
        .into();
    let url = latest_page(tool);
    let resp = http
        .get(&url)
        .call()
        .map_err(|e| format!("cannot reach github.com: {e}"))?;
    let status = resp.status();
    if !status.is_redirection() {
        return Err(format!(
            "unexpected answer from github.com: HTTP {}",
            status.as_u16()
        ));
    }
    let location = resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .ok_or("github.com sent no release location")?;
    version_from_location(location, tool)
        .ok_or_else(|| format!("no published release ({location})"))
}

/// Checks `tool` running at `current` (honours the off switch). `agent`: see [`latest_version`].
pub fn check_tool(tool: &str, current: &str, agent: &str) -> Check {
    if disabled() {
        return Check::Disabled {
            current: current.to_string(),
        };
    }
    match latest_version(tool, agent) {
        Ok(latest) => compare(current, &latest, tool),
        Err(reason) => Check::Failed {
            current: current.to_string(),
            reason,
        },
    }
}

/// The User-Agent of this tool: `rv-<tool>/<version>`.
pub fn user_agent() -> String {
    format!("{}/{}", crate::TOOL_NAME, crate::TOOL_VERSION)
}

/// Checks this tool.
pub fn check() -> Check {
    check_tool(crate::TOOL_NAME, crate::TOOL_VERSION, &user_agent())
}

/// The JSON object `update-check --json` prints.
pub fn report(tool: &str, c: &Check) -> serde_json::Value {
    let mut v = serde_json::to_value(c).unwrap_or_default();
    v["schema"] = SCHEMA.into();
    v["tool"] = tool.into();
    v["release_page"] = latest_page(tool).into();
    v
}

/// A check running in the background (the GUI starts one at start-up and polls it each frame).
pub struct Background {
    rx: Option<std::sync::mpsc::Receiver<Check>>,
    result: Option<Check>,
}

impl Background {
    /// Starts checking this tool on a thread; when turned off, nothing is started and the result is `Disabled`.
    pub fn start() -> Self {
        if disabled() {
            return Background {
                rx: None,
                result: Some(Check::Disabled {
                    current: crate::TOOL_VERSION.to_string(),
                }),
            };
        }
        let (tx, rx) = std::sync::mpsc::channel();
        let spawned = std::thread::Builder::new()
            .name("rv-update-check".into())
            .spawn(move || {
                let _ = tx.send(check());
            });
        match spawned {
            Ok(_) => Background {
                rx: Some(rx),
                result: None,
            },
            Err(e) => Background {
                rx: None,
                result: Some(Check::Failed {
                    current: crate::TOOL_VERSION.to_string(),
                    reason: e.to_string(),
                }),
            },
        }
    }

    /// The result once the check finished (None while it runs).
    pub fn poll(&mut self) -> Option<&Check> {
        if self.result.is_none()
            && let Some(rx) = &self.rx
        {
            match rx.try_recv() {
                Ok(c) => self.result = Some(c),
                Err(std::sync::mpsc::TryRecvError::Empty) => {}
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    self.result = Some(Check::Failed {
                        current: crate::TOOL_VERSION.to_string(),
                        reason: "the check stopped".into(),
                    })
                }
            }
        }
        self.result.as_ref()
    }
}

/// The desktop app's start-up check (one per process; [`start_gui_check`] is called by the GUI binary's `main()`
/// only, so tests and screenshots that build the window never contact the network).
static GUI_CHECK: std::sync::Mutex<Option<Background>> = std::sync::Mutex::new(None);

/// Starts the desktop app's check once per process.
pub fn start_gui_check() {
    if let Ok(mut g) = GUI_CHECK.lock()
        && g.is_none()
    {
        *g = Some(Background::start());
    }
}

/// Starts the desktop app's check again (RV Hub, when its setting turns the check back on).
pub fn restart_gui_check() {
    if let Ok(mut g) = GUI_CHECK.lock() {
        *g = Some(Background::start());
    }
}

/// The desktop app's check: None when it was never started; `Some(None)` while it runs; `Some(Some(check))` once
/// it finished.
pub fn gui_check() -> Option<Option<Check>> {
    let mut g = GUI_CHECK.lock().ok()?;
    let b = g.as_mut()?;
    Some(b.poll().cloned())
}

/// The banner text of a check in the interface language (`en`, `es`, `fr`): Some only when a newer release is
/// published (an up-to-date, turned-off or failed check shows nothing in the GUI).
pub fn banner(c: &Check, title: &str, lang: &str) -> Option<String> {
    let Check::Available {
        current, latest, ..
    } = c
    else {
        return None;
    };
    Some(match lang {
        "es" => format!(
            "Hay una versión nueva de {title}: {latest} (usted usa {current}). Descárguela y verifique su firma antes de usarla."
        ),
        "fr" => format!(
            "Une nouvelle version de {title} est publiée : {latest} (vous utilisez {current}). Téléchargez-la et vérifiez sa signature avant de l'utiliser."
        ),
        _ => format!(
            "A new release of {title} is published: {latest} (you are using {current}). Download it and verify its signature before use."
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_and_locations() {
        assert_eq!(version_triple("0.3.0"), Some((0, 3, 0)));
        assert_eq!(version_triple("v1.12.7"), Some((1, 12, 7)));
        for bad in [
            "",
            "1.2",
            "1.2.3.4",
            "1.2.3-rc.1",
            "1.2.x",
            "v",
            "1..3",
            " 1.2.3x",
        ] {
            assert_eq!(version_triple(bad), None, "{bad:?}");
        }
        let t = "rv-timeline";
        assert_eq!(
            version_from_location(
                "https://github.com/Panacota96/rv-timeline/releases/tag/v0.3.0",
                t
            )
            .as_deref(),
            Some("0.3.0")
        );
        assert_eq!(
            version_from_location("/Panacota96/rv-timeline/releases/tag/v0.10.2", t).as_deref(),
            Some("0.10.2")
        );
        for bad in [
            "https://github.com/Panacota96/rv-timeline/releases",
            "https://github.com/Panacota96/rv-hub/releases/tag/v0.6.3",
            "https://github.com/Other/rv-timeline/releases/tag/v9.9.9",
            "https://example.org/Panacota96/rv-timeline/releases/tag/v9.9.9",
            "https://github.com/Panacota96/rv-timeline/releases/tag/v1.0.0-rc.1",
            "https://github.com/Panacota96/rv-timeline/releases/tag/latest",
        ] {
            assert_eq!(version_from_location(bad, t), None, "{bad}");
        }
    }

    #[test]
    fn compare_and_texts() {
        let t = "rv-timeline";
        let a = compare("0.2.3", "0.3.0", t);
        assert_eq!(
            a,
            Check::Available {
                current: "0.2.3".into(),
                latest: "0.3.0".into(),
                url: "https://github.com/Panacota96/rv-timeline/releases/tag/v0.3.0".into()
            }
        );
        assert_eq!(a.status(), "available");
        assert!(a.line(t).contains("0.3.0 is available"));
        assert_eq!(compare("0.10.0", "0.9.9", t).status(), "up_to_date");
        assert_eq!(compare("0.3.0", "0.3.0", t).status(), "up_to_date");
        assert_eq!(compare("dev", "0.3.0", t).status(), "failed");
        let b = banner(&a, "RV Timeline", "fr").unwrap();
        assert!(
            b.contains("0.3.0") && b.contains("0.2.3") && b.contains("signature"),
            "{b}"
        );
        assert!(banner(&a, "RV Timeline", "es").unwrap().contains("firma"));
        assert!(
            banner(&a, "RV Timeline", "xx")
                .unwrap()
                .starts_with("A new release")
        );
        assert_eq!(
            banner(&compare("0.3.0", "0.3.0", t), "RV Timeline", "en"),
            None
        );
        let j = report(t, &a);
        assert_eq!(
            (
                j["schema"].as_str(),
                j["status"].as_str(),
                j["latest"].as_str()
            ),
            (Some(SCHEMA), Some("available"), Some("0.3.0"))
        );
        assert_eq!(
            j["release_page"],
            "https://github.com/Panacota96/rv-timeline/releases/latest"
        );
    }

    #[test]
    fn off_switch_values() {
        for (v, off) in [
            (None, false),
            (Some(""), false),
            (Some("0"), false),
            (Some("1"), true),
            (Some("yes"), true),
        ] {
            assert_eq!(env_says_off(v), off, "{v:?}");
        }
        assert!(off_file().is_none_or(|f| f.ends_with(OFF_FILE)));
        assert!(latest_version("../etc", "x").is_err());
        assert!(latest_version("rv-Hub", "x").is_err());
        for ok in ["rv-hub", "rv-whatsapp-rsmf", "rv-jpegcarve", "rv-mp4"] {
            assert!(is_tool_name(ok), "{ok}");
        }
        for bad in [
            "rv-",
            "rv--x",
            "rv-x-",
            "rv-x/../y",
            "rv-X",
            "hub",
            "rv-a b",
            "rv-é",
        ] {
            assert!(!is_tool_name(bad), "{bad}");
        }
    }

    /// The real check against github.com (network): `cargo test -- --ignored update::tests::live`.
    #[test]
    #[ignore = "contacts github.com"]
    fn live() {
        let v = latest_version("rv-hub", "rv-test/0.0.0").unwrap();
        assert!(version_triple(&v).is_some(), "{v}");
        assert_eq!(compare("0.0.1", &v, "rv-hub").status(), "available");
    }
}
