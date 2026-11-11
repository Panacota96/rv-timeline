//! Windows only: embeds the Rakvor icon and the version/company details in the .exe, so Explorer,
//! the taskbar and desktop shortcuts show the RV mark. Other platforms: nothing to do.
fn main() {
    println!("cargo:rerun-if-changed=../../assets/brand/rv.ico");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    let version = std::fs::read_to_string("../../version.txt").unwrap_or_default();
    println!("cargo:rerun-if-changed=../../version.txt");
    let mut res = winresource::WindowsResource::new();
    res.set_icon("../../assets/brand/rv.ico")
        .set("ProductName", "RV Timeline")
        .set("CompanyName", "Rakvor")
        .set(
            "LegalCopyright",
            "Rakvor. Source-auditable licence, see LICENSE.",
        )
        .set("FileDescription", "RV Timeline command line")
        .set("ProductVersion", version.trim());
    res.compile()
        .expect("embedding the Windows icon (needs rc.exe from the Windows SDK)");
}
