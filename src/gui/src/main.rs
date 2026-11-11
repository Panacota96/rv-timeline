// No console window behind the GUI on Windows.
#![cfg_attr(windows, windows_subsystem = "windows")]

use eframe::egui;

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            // Title-bar and taskbar icon (the .exe file icon comes from build.rs).
            .with_icon(
                eframe::icon_data::from_png_bytes(include_bytes!(
                    "../../../assets/brand/rv-mark.png"
                ))
                .expect("bundled icon is a valid PNG"),
            )
            .with_title("RV Timeline — Rakvor")
            .with_inner_size([860.0, 720.0])
            .with_min_inner_size([640.0, 520.0])
            .with_drag_and_drop(true),
        // wgpu falls back to a software adapter (WARP on Windows), so the GUI also runs on
        // forensic VMs without a GPU driver.
        renderer: eframe::Renderer::Wgpu,
        ..Default::default()
    };
    eframe::run_native(
        "RV Timeline",
        options,
        // Files or folders dropped on the .exe icon (or passed on the command line) are pre-loaded;
        // `--case-dir DIR` (RV Hub) presets the case folder.
        Box::new(|_cc| {
            Ok(Box::new(rv_timeline_gui::app::HashInvApp::from_launch(
                rv_timeline_gui::launch::parse_launch_args(std::env::args_os().skip(1)),
            )))
        }),
    )
}
