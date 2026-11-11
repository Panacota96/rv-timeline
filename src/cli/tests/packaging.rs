//! Static checks of the Windows installer script (packaging/windows/installer.iss).

use std::path::Path;

fn installer() -> String {
    let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../packaging/windows/installer.iss");
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {}", p.display(), e))
}

/// The installer identity of every Rakvor tool. Two installers with the same AppId upgrade or uninstall each
/// other (rv-imgauth 0.2.0 shipped with rv-pdfauth's). A new tool adds its AppId here, in every tool repo.
const THIS_TOOL: &str = "rv-timeline";
const RAKVOR_APP_IDS: [(&str, &str); 11] = [
    ("rv-hashinv", "6D3F3B0E-5B7A-4B2C-9E61-2A1C7D4E9F10"),
    ("rv-pdfauth", "B2454915-B966-44CD-9C5B-5413F38185AE"),
    ("rv-rsmf", "7E0DA535-8638-4E9D-8680-ED046DCA9F45"),
    ("rv-imgauth", "04A0C3C3-4929-42ED-81F7-93DB361940C8"),
    ("rv-hub", "703D49A5-7B83-4C62-A97F-ED13C341CC23"),
    ("rv-certcheck", "32343DE5-B0E4-4454-8A42-A5CF82EEC9BF"),
    ("rv-mailauth", "0D5428B0-B438-4B0F-804F-C48582CC8A7B"),
    ("rv-timeline", "BE690C03-DA5F-42F0-9284-A86D5FF89D0E"),
    ("rv-triage", "EED6D788-369E-4217-B0D7-83E4D8A93196"),
    ("rv-report", "D943D333-1B25-4E70-B3FC-2256DADA9F4B"),
    ("rv-avauth", "60B92A10-F369-4876-88D0-728ADD924167"),
];

#[test]
fn installer_app_id_is_this_tools_own() {
    let iss = installer();
    let line = iss
        .lines()
        .find(|l| l.starts_with("AppId="))
        .expect("installer.iss has an AppId line");
    // Inno Setup escapes the opening brace: AppId={{GUID}
    let id = line
        .strip_prefix("AppId={{")
        .and_then(|l| l.strip_suffix('}'))
        .unwrap_or_else(|| panic!("AppId must be written {{{{GUID}}: {}", line));
    let (own_tool, own_id) = RAKVOR_APP_IDS
        .iter()
        .find(|(t, _)| *t == THIS_TOOL)
        .copied()
        .unwrap_or_else(|| panic!("{} is not in RAKVOR_APP_IDS", THIS_TOOL));
    assert_eq!(id, own_id, "{} installer AppId", own_tool);
    for (other, other_id) in RAKVOR_APP_IDS {
        if other != own_tool {
            assert_ne!(
                id, other_id,
                "{} shares its installer AppId with {}",
                own_tool, other
            );
        }
    }
    let mut ids: Vec<&str> = RAKVOR_APP_IDS.iter().map(|(_, i)| *i).collect();
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), RAKVOR_APP_IDS.len(), "AppIds are unique");
}
