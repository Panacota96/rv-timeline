//! Renders the window headless (no display, no GPU) to PNG files, for the documentation:
//!
//!     cargo run -p rv-timeline-gui --example gui_screenshot -- docs/images [en|es|fr]
//!
//! It builds the timeline of a copy of `examples/sample/case` from GUI settings (display zone America/Bogota),
//! reads the build back from its audited outputs and writes:
//! - `gui-main.png`: the main window after the finished build (settings, runs table, signals);
//! - `gui-timeline.png`: the timeline view with a signal selected (its events highlighted) and one event open.
//!
//! egui's tessellated meshes are rasterised on the CPU (textured triangles, premultiplied alpha), so the
//! picture is what the window draws, minus the GPU.
#![forbid(unsafe_code)]

use eframe::egui;
use egui::epaint::{ClippedPrimitive, Color32, ImageData, Primitive, TextureId};
use rv_timeline_gui::app::HashInvApp;
use rv_timeline_gui::state::GuiState;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

struct Tex {
    w: usize,
    h: usize,
    px: Vec<Color32>,
}

impl Tex {
    /// Bilinear sample of premultiplied texels, clamped at the edges.
    fn sample(&self, u: f32, v: f32) -> [f32; 4] {
        let x = (u * self.w as f32 - 0.5).clamp(0.0, (self.w - 1) as f32);
        let y = (v * self.h as f32 - 0.5).clamp(0.0, (self.h - 1) as f32);
        let (x0, y0) = (x.floor() as usize, y.floor() as usize);
        let (x1, y1) = ((x0 + 1).min(self.w - 1), (y0 + 1).min(self.h - 1));
        let (fx, fy) = (x - x0 as f32, y - y0 as f32);
        let at = |x: usize, y: usize| {
            let c = self.px[y * self.w + x];
            [c.r() as f32, c.g() as f32, c.b() as f32, c.a() as f32]
        };
        let (a, b, c, d) = (at(x0, y0), at(x1, y0), at(x0, y1), at(x1, y1));
        let mut o = [0.0; 4];
        for i in 0..4 {
            let top = a[i] + (b[i] - a[i]) * fx;
            let bot = c[i] + (d[i] - c[i]) * fx;
            o[i] = (top + (bot - top) * fy) / 255.0;
        }
        o
    }
}

fn rasterise(
    prims: &[ClippedPrimitive],
    textures: &HashMap<TextureId, Tex>,
    ppp: f32,
    (width, height): (usize, usize),
) -> Vec<[f32; 4]> {
    let mut canvas = vec![[0.0f32, 0.0, 0.0, 1.0]; width * height];
    for p in prims {
        let Primitive::Mesh(mesh) = &p.primitive else {
            continue;
        };
        let Some(tex) = textures.get(&mesh.texture_id) else {
            continue;
        };
        let cx0 = (p.clip_rect.min.x * ppp).max(0.0).floor() as i64;
        let cy0 = (p.clip_rect.min.y * ppp).max(0.0).floor() as i64;
        let cx1 = ((p.clip_rect.max.x * ppp).ceil() as i64).min(width as i64);
        let cy1 = ((p.clip_rect.max.y * ppp).ceil() as i64).min(height as i64);
        for t in mesh.indices.as_chunks::<3>().0 {
            let v = [
                &mesh.vertices[t[0] as usize],
                &mesh.vertices[t[1] as usize],
                &mesh.vertices[t[2] as usize],
            ];
            let pt: Vec<[f32; 2]> = v.iter().map(|v| [v.pos.x * ppp, v.pos.y * ppp]).collect();
            let area = (pt[1][0] - pt[0][0]) * (pt[2][1] - pt[0][1])
                - (pt[2][0] - pt[0][0]) * (pt[1][1] - pt[0][1]);
            if area.abs() < 1e-9 {
                continue;
            }
            let minx = pt.iter().map(|p| p[0]).fold(f32::MAX, f32::min).floor() as i64;
            let maxx = pt.iter().map(|p| p[0]).fold(f32::MIN, f32::max).ceil() as i64;
            let miny = pt.iter().map(|p| p[1]).fold(f32::MAX, f32::min).floor() as i64;
            let maxy = pt.iter().map(|p| p[1]).fold(f32::MIN, f32::max).ceil() as i64;
            for y in miny.max(cy0)..maxy.min(cy1) {
                for x in minx.max(cx0)..maxx.min(cx1) {
                    let (px, py) = (x as f32 + 0.5, y as f32 + 0.5);
                    let e = |a: [f32; 2], b: [f32; 2]| {
                        (b[0] - a[0]) * (py - a[1]) - (b[1] - a[1]) * (px - a[0])
                    };
                    let w0 = e(pt[1], pt[2]) / area;
                    let w1 = e(pt[2], pt[0]) / area;
                    let w2 = e(pt[0], pt[1]) / area;
                    if w0 < 0.0 || w1 < 0.0 || w2 < 0.0 {
                        continue;
                    }
                    let u = w0 * v[0].uv.x + w1 * v[1].uv.x + w2 * v[2].uv.x;
                    let vv = w0 * v[0].uv.y + w1 * v[1].uv.y + w2 * v[2].uv.y;
                    let s = tex.sample(u, vv);
                    let col = |i: usize| {
                        let c = |v: &egui::epaint::Vertex| v.color.to_array()[i] as f32 / 255.0;
                        w0 * c(v[0]) + w1 * c(v[1]) + w2 * c(v[2])
                    };
                    let src = [s[0] * col(0), s[1] * col(1), s[2] * col(2), s[3] * col(3)];
                    let d = &mut canvas[y as usize * width + x as usize];
                    for i in 0..4 {
                        d[i] = src[i] + d[i] * (1.0 - src[3]);
                    }
                }
            }
        }
    }
    canvas
}

/// Runs a few frames of `app` at `size` and writes the picture to `target`.
fn render(app: &mut HashInvApp, size: (usize, usize), target: &Path) {
    let (w, h) = size;
    let ctx = egui::Context::default();
    // A fresh context per picture: the theme is applied by the app only once per window.
    rv_timeline_gui::app::apply_theme(&ctx);
    let mut textures: HashMap<TextureId, Tex> = HashMap::new();
    let mut last = None;
    for frame in 0..4 {
        let raw = egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(w as f32, h as f32),
            )),
            time: Some(frame as f64 * 0.1),
            ..Default::default()
        };
        let mut output = ctx.run_ui(raw, |ui| app.draw(ui));
        for (id, deltas) in &output.textures_delta.set {
            for d in deltas {
                let ImageData::Color(img) = &d.image;
                match d.pos {
                    None => {
                        textures.insert(
                            *id,
                            Tex {
                                w: img.size[0],
                                h: img.size[1],
                                px: img.pixels.clone(),
                            },
                        );
                    }
                    Some([x0, y0]) => {
                        let t = textures.get_mut(id).expect("patch of a known texture");
                        for y in 0..img.size[1] {
                            for x in 0..img.size[0] {
                                t.px[(y0 + y) * t.w + x0 + x] = img.pixels[y * img.size[0] + x];
                            }
                        }
                    }
                }
            }
        }
        // Applied above (this renderer keeps every texture until the end).
        output.textures_delta.clear();
        last = Some(output);
    }
    let output = last.expect("frames ran");
    let ppp = output.pixels_per_point;
    let prims = ctx.tessellate(output.shapes, ppp);
    let canvas = rasterise(&prims, &textures, ppp, size);
    let rgba: Vec<u8> = canvas
        .iter()
        .flat_map(|p| {
            let a = p[3].clamp(1e-6, 1.0);
            [p[0] / a, p[1] / a, p[2] / a, 1.0].map(|c| (c.clamp(0.0, 1.0) * 255.0).round() as u8)
        })
        .collect();
    let file = std::fs::File::create(target).expect("create png");
    let mut enc = png::Encoder::new(std::io::BufWriter::new(file), w as u32, h as u32);
    enc.set_color(png::ColorType::Rgba);
    enc.set_depth(png::BitDepth::Eight);
    enc.write_header()
        .expect("png")
        .write_image_data(&rgba)
        .expect("png data");
    println!(
        "wrote {} ({w}x{h}, {} meshes)",
        target.display(),
        prims.len()
    );
}

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).expect("folder");
    for e in std::fs::read_dir(from).expect("read folder") {
        let e = e.expect("entry");
        let t = to.join(e.file_name());
        if e.file_type().expect("type").is_dir() {
            copy_dir(&e.path(), &t);
        } else {
            std::fs::copy(e.path(), &t).expect("copy");
        }
    }
}

fn main() {
    let mut args = std::env::args().skip(1);
    let dir = PathBuf::from(args.next().unwrap_or_else(|| ".".into()));
    let ui_lang = args.next().unwrap_or_else(|| "en".into());
    std::fs::create_dir_all(&dir).expect("output folder");
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    // The build writes into the case folder: work on a copy (the sample stays untouched).
    let case = std::env::temp_dir().join("rv-timeline-shot");
    let _ = std::fs::remove_dir_all(&case);
    copy_dir(&root.join("examples/sample/case"), &case);

    let mut s = GuiState {
        timestamp: false,
        actor: "Examiner".into(),
        ..Default::default()
    };
    s.set_case_dir(&case.display().to_string());
    s.set_display_zone("America/Bogota").expect("zone");
    let (cfg, opts) = s.to_config().expect("config");
    s.start();
    let cancel = std::sync::atomic::AtomicBool::new(false);
    rv_timeline_core::run::run_timeline(&cfg, &opts, &mut |e| s.apply(e), &cancel).expect("build");
    assert!(s.load_results(), "view: {:?}", s.view_error);
    s.set_ui_lang(&ui_lang);
    // Show the case folder as the examiner would see it in the repository (no temp path, no user name).
    s.case_dir = r"examples\sample\case".into();
    let mut app = HashInvApp::from_state(s);
    render(&mut app, (1400, 1480), &dir.join("gui-main.png"));

    let st = app.state_mut();
    let v = st.view.as_ref().expect("view");
    let n = (0..v.signals.len())
        .find(|&n| {
            !v.signal_rows[n].is_empty()
                && v.signals[n].severity >= rv_timeline_core::model::Severity::Medium
        })
        .or_else(|| (0..v.signals.len()).find(|&n| !v.signal_rows[n].is_empty()))
        .expect("a signal naming events");
    let first = v.signal_rows[n][0];
    st.open_view_page();
    st.select_signal(Some(n));
    st.select_event(Some(first));
    render(&mut app, (1600, 1000), &dir.join("gui-timeline.png"));
    let _ = std::fs::remove_dir_all(&case);
}
