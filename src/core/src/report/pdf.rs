//! A small, dependency-free PDF writer for print-ready reports.
//!
//! Uses the 14 standard fonts (Helvetica, Helvetica-Bold, Courier) with WinAnsiEncoding, which covers
//! English, Spanish and French (á é í ó ú ñ ü ç à è ê ë î ï ô œ « » € …). Characters outside WinAnsi
//! become '?'. Upgrade path for richer layout or other scripts: Typst or printpdf with embedded fonts.

use std::fmt::Write as _;

const PAGE_W: f32 = 595.0; // A4 in points
const PAGE_H: f32 = 842.0;
const MARGIN: f32 = 50.0;
const BOTTOM: f32 = 62.0;
const CONTENT_W: f32 = PAGE_W - 2.0 * MARGIN;
const KEY_W: f32 = 165.0;
const BAND_H: f32 = 62.0; // Rakvor header band on every page
const TOP: f32 = PAGE_H - BAND_H - 30.0;
const SIG_CONTENTS_BYTES: usize = 16384; // room for the CMS signature (certificate chain included)

#[derive(Clone, Debug)]
pub enum Block {
    Brand(String),
    Title(String),
    Subtitle(String),
    Heading(String),
    Para(String),
    Note(String),
    Mono(String),
    Bullet(String),
    Kv(Vec<(String, String)>),
    /// Small labelled box: (badge text, title, rows of key/value)
    Finding {
        badge: String,
        title: String,
        rows: Vec<(String, String)>,
    },
    Status(String),
    Space(f32),
    /// Table with a header row and `rows` empty rows to fill in by hand (custody transfers).
    Grid {
        header: Vec<String>,
        widths: Vec<f32>,
        rows: usize,
        row_h: f32,
    },
    /// Signature lines side by side: label under each line.
    SignLines(Vec<String>),
}

#[derive(Clone, Copy, PartialEq)]
enum Font {
    Regular,
    Bold,
    Mono,
}

impl Font {
    fn res(self) -> &'static str {
        match self {
            Font::Regular => "F1",
            Font::Bold => "F2",
            Font::Mono => "F3",
        }
    }
}

// Advance widths (1/1000 em) for ASCII 32..=126 from the Adobe AFM files.
const HELV: [u16; 95] = [
    278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278, 278, 556, 556, 556,
    556, 556, 556, 556, 556, 556, 556, 278, 278, 584, 584, 584, 556, 1015, 667, 667, 722, 722, 667,
    611, 778, 722, 278, 500, 667, 556, 833, 722, 778, 667, 778, 722, 667, 611, 722, 667, 944, 667,
    667, 611, 278, 278, 278, 469, 556, 333, 556, 556, 500, 556, 556, 278, 556, 556, 222, 222, 500,
    222, 833, 556, 556, 556, 556, 333, 500, 278, 556, 500, 722, 500, 500, 500, 334, 260, 334, 584,
];
const HELV_BOLD: [u16; 95] = [
    278, 333, 474, 556, 556, 889, 722, 238, 333, 333, 389, 584, 278, 333, 278, 278, 556, 556, 556,
    556, 556, 556, 556, 556, 556, 556, 333, 333, 584, 584, 584, 611, 975, 722, 722, 722, 722, 667,
    611, 778, 722, 278, 556, 722, 611, 833, 722, 778, 667, 778, 722, 667, 611, 722, 667, 944, 667,
    667, 611, 333, 278, 333, 584, 556, 333, 556, 611, 556, 611, 556, 333, 611, 611, 278, 278, 556,
    278, 889, 611, 611, 611, 611, 389, 556, 333, 611, 556, 778, 556, 556, 500, 389, 280, 389, 584,
];

fn char_width(c: char, font: Font, size: f32) -> f32 {
    let units = match font {
        Font::Mono => 600,
        Font::Regular | Font::Bold => {
            let table = if font == Font::Bold {
                &HELV_BOLD
            } else {
                &HELV
            };
            let base = match c {
                ' '..='~' => c,
                'á' | 'à' | 'â' | 'ä' | 'ã' => 'a',
                'é' | 'è' | 'ê' | 'ë' => 'e',
                'í' | 'ì' | 'î' | 'ï' => 'i',
                'ó' | 'ò' | 'ô' | 'ö' | 'õ' => 'o',
                'ú' | 'ù' | 'û' | 'ü' => 'u',
                'ñ' => 'n',
                'ç' => 'c',
                'Á' | 'À' | 'Â' => 'A',
                'É' | 'È' | 'Ê' => 'E',
                'Ó' | 'Ô' => 'O',
                'Ú' => 'U',
                'Ñ' => 'N',
                'Ç' => 'C',
                _ => 'W', // unknown: assume wide so text never overflows
            };
            table[(base as usize) - 32]
        }
    };
    units as f32 * size / 1000.0
}

fn text_width(s: &str, font: Font, size: f32) -> f32 {
    s.chars().map(|c| char_width(c, font, size)).sum()
}

/// Greedy word wrap; words longer than the line are broken by characters (hashes, paths).
fn wrap(text: &str, font: Font, size: f32, width: f32) -> Vec<String> {
    let mut lines = Vec::new();
    for para in text.split('\n') {
        let mut line = String::new();
        for word in para.split(' ') {
            let candidate = if line.is_empty() {
                word.to_string()
            } else {
                format!("{} {}", line, word)
            };
            if text_width(&candidate, font, size) <= width {
                line = candidate;
                continue;
            }
            if !line.is_empty() {
                lines.push(std::mem::take(&mut line));
            }
            let mut chunk = String::new();
            for c in word.chars() {
                if text_width(&chunk, font, size) + char_width(c, font, size) > width
                    && !chunk.is_empty()
                {
                    lines.push(std::mem::take(&mut chunk));
                }
                chunk.push(c);
            }
            line = chunk;
        }
        lines.push(line);
    }
    lines
}

/// Encodes to WinAnsi and escapes for a PDF literal string.
fn pdf_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('(');
    for c in s.chars() {
        let b: u8 = match c {
            '\u{20AC}' => 0x80,
            '\u{2026}' => 0x85,
            '\u{2018}' => 0x91,
            '\u{2019}' => 0x92,
            '\u{201C}' => 0x93,
            '\u{201D}' => 0x94,
            '\u{2022}' => 0x95,
            '\u{2013}' => 0x96,
            '\u{2014}' => 0x97,
            '\u{2122}' => 0x99,
            '\u{0152}' => 0x8C,
            '\u{0153}' => 0x9C,
            '\u{00A0}'..='\u{00FF}' => c as u32 as u8,
            ' '..='~' => c as u8,
            _ => b'?',
        };
        match b {
            b'(' | b')' | b'\\' => {
                out.push('\\');
                out.push(b as char);
            }
            0x20..=0x7E => out.push(b as char),
            _ => {
                let _ = write!(out, "\\{:03o}", b);
            }
        }
    }
    out.push(')');
    out
}

struct Layout {
    pages: Vec<String>,
    cur: String,
    y: f32,
}

impl Layout {
    fn new() -> Layout {
        Layout {
            pages: Vec::new(),
            cur: String::new(),
            y: TOP,
        }
    }

    fn ensure(&mut self, h: f32) {
        if self.y - h < BOTTOM {
            self.pages.push(std::mem::take(&mut self.cur));
            self.y = TOP;
        }
    }

    fn text(&mut self, x: f32, y: f32, font: Font, size: f32, rgb: (f32, f32, f32), s: &str) {
        let _ = writeln!(
            self.cur,
            "{:.3} {:.3} {:.3} rg BT /{} {} Tf {:.2} {:.2} Td {} Tj ET",
            rgb.0,
            rgb.1,
            rgb.2,
            font.res(),
            size,
            x,
            y,
            pdf_string(s)
        );
    }

    fn rule(&mut self, y: f32, w: f32, rgb: (f32, f32, f32)) {
        let _ = writeln!(
            self.cur,
            "{:.3} {:.3} {:.3} RG {} w {} {:.2} m {} {:.2} l S",
            rgb.0,
            rgb.1,
            rgb.2,
            w,
            MARGIN,
            y,
            PAGE_W - MARGIN,
            y
        );
    }

    fn rect(&mut self, x: f32, y: f32, w: f32, h: f32, rgb: (f32, f32, f32)) {
        let _ = writeln!(
            self.cur,
            "{:.3} {:.3} {:.3} rg {:.2} {:.2} {:.2} {:.2} re f",
            rgb.0, rgb.1, rgb.2, x, y, w, h
        );
    }

    fn lines(
        &mut self,
        x: f32,
        width: f32,
        font: Font,
        size: f32,
        rgb: (f32, f32, f32),
        text: &str,
    ) {
        let lead = size * 1.35;
        for l in wrap(text, font, size, width) {
            self.ensure(lead);
            self.y -= lead;
            self.text(x, self.y, font, size, rgb, &l);
        }
    }

    fn kv(&mut self, x: f32, width: f32, rows: &[(String, String)]) {
        const SIZE: f32 = 9.0;
        let lead = SIZE * 1.35;
        for (k, v) in rows {
            let mono = looks_like_hash(v);
            let vf = if mono { Font::Mono } else { Font::Regular };
            let vs = if mono { 8.0 } else { SIZE };
            let kl = wrap(k, Font::Regular, SIZE, KEY_W - 10.0);
            let vl = wrap(v, vf, vs, width - KEY_W);
            let n = kl.len().max(vl.len());
            self.ensure(lead * n as f32 + 3.0);
            let top = self.y;
            for (i, l) in kl.iter().enumerate() {
                self.text(
                    x,
                    top - lead * (i as f32 + 1.0),
                    Font::Regular,
                    SIZE,
                    MUTED,
                    l,
                );
            }
            for (i, l) in vl.iter().enumerate() {
                self.text(x + KEY_W, top - lead * (i as f32 + 1.0), vf, vs, INK, l);
            }
            self.y = top - lead * n as f32 - 3.0;
        }
    }
}

// Rakvor palette (pages stay light for printing; the brand lives in the header band).
const INK: (f32, f32, f32) = (0.051, 0.067, 0.090); // #0D1117
const MUTED: (f32, f32, f32) = (0.278, 0.329, 0.404);
const ACCENT: (f32, f32, f32) = (0.165, 0.361, 1.0); // #2A5CFF
const LINE: (f32, f32, f32) = (0.894, 0.906, 0.925);
const NIGHT: (f32, f32, f32) = (0.051, 0.067, 0.090); // #0D1117
const NIGHT2: (f32, f32, f32) = (0.102, 0.122, 0.149); // #1A1F26
const VIOLET: (f32, f32, f32) = (0.420, 0.0, 1.0); // #6B00FF
const CYAN: (f32, f32, f32) = (0.0, 0.898, 1.0); // #00E5FF
const MIST: (f32, f32, f32) = (0.902, 0.902, 0.902); // #E6E6E6

/// Texts printed on every page.
pub struct Meta<'a> {
    pub title: &'a str,
    pub footer: &'a str,
    pub page_word: &'a str,
    pub of_word: &'a str,
    pub producer: &'a str,
    pub descriptor: &'a str,
    pub tagline: &'a str,
}

/// Signs the bytes covered by /ByteRange and returns a DER CMS SignedData (detached).
pub type SignFn<'a> = &'a dyn Fn(&[u8]) -> Result<Vec<u8>, String>;

fn band(meta: &Meta) -> String {
    let mut c = String::new();
    let rg = |c: &mut String, k: (f32, f32, f32)| {
        let _ = write!(c, "{:.3} {:.3} {:.3} rg ", k.0, k.1, k.2);
    };
    rg(&mut c, NIGHT);
    let _ = writeln!(c, "0 {:.2} {} {} re f", PAGE_H - BAND_H, PAGE_W, BAND_H);
    for (i, k) in [ACCENT, VIOLET, CYAN].iter().enumerate() {
        rg(&mut c, *k);
        let _ = writeln!(
            c,
            "{:.2} {:.2} {:.2} 2.2 re f",
            i as f32 * PAGE_W / 3.0,
            PAGE_H - BAND_H - 2.2,
            PAGE_W / 3.0
        );
    }
    let (x, y, s) = (MARGIN, PAGE_H - BAND_H + 10.0, 42.0);
    rg(&mut c, NIGHT2);
    let _ = writeln!(
        c,
        "{:.3} {:.3} {:.3} RG 1.6 w {} {} {} {} re B",
        ACCENT.0, ACCENT.1, ACCENT.2, x, y, s, s
    );
    rg(&mut c, MIST);
    let _ = writeln!(
        c,
        "BT /F2 17 Tf {:.2} {:.2} Td (RV) Tj ET",
        x + 8.5,
        y + 15.0
    );
    rg(&mut c, CYAN);
    let _ = writeln!(c, "{:.2} {:.2} 22 2 re f", x + 10.0, y + 8.0);
    rg(&mut c, MIST);
    let _ = writeln!(
        c,
        "BT /F2 13 Tf 4 Tc {:.2} {:.2} Td (RAKVOR) Tj ET 0 Tc",
        x + s + 14.0,
        y + 22.0
    );
    rg(&mut c, CYAN);
    let _ = writeln!(
        c,
        "BT /F1 7.5 Tf {:.2} {:.2} Td {} Tj ET",
        x + s + 14.0,
        y + 9.0,
        pdf_string(meta.descriptor)
    );
    c
}

/// Hashes and long paths (no spaces, 32+ characters) are set in monospace and wrapped by character.
fn looks_like_hash(v: &str) -> bool {
    v.chars().count() >= 32 && !v.contains(' ')
}

/// Renders blocks to a complete PDF. `footer` is printed on every page followed by "page n / m".
pub fn render(blocks: &[Block], meta: &Meta, sign: Option<SignFn>) -> Result<Vec<u8>, String> {
    let (title, footer, page_word, of_word, producer) = (
        meta.title,
        meta.footer,
        meta.page_word,
        meta.of_word,
        meta.producer,
    );
    let mut l = Layout::new();
    for b in blocks {
        match b {
            Block::Brand(s) => {
                l.ensure(14.0);
                l.y -= 10.0;
                l.text(MARGIN, l.y, Font::Bold, 8.0, ACCENT, s);
            }
            Block::Title(s) => {
                l.y -= 6.0;
                l.lines(MARGIN, CONTENT_W, Font::Bold, 18.0, INK, s);
            }
            Block::Subtitle(s) => {
                l.lines(MARGIN, CONTENT_W, Font::Regular, 10.0, MUTED, s);
                l.y -= 8.0;
                l.rule(l.y, 2.0, ACCENT);
                l.y -= 8.0;
            }
            Block::Heading(s) => {
                l.ensure(40.0);
                l.y -= 10.0;
                l.lines(MARGIN, CONTENT_W, Font::Bold, 12.0, INK, s);
                l.y -= 4.0;
                l.rule(l.y, 0.6, LINE);
                l.y -= 2.0;
            }
            Block::Para(s) => {
                l.lines(MARGIN, CONTENT_W, Font::Regular, 9.5, INK, s);
                l.y -= 3.0;
            }
            Block::Note(s) => {
                l.y -= 2.0;
                l.lines(
                    MARGIN + 8.0,
                    CONTENT_W - 8.0,
                    Font::Bold,
                    9.5,
                    (0.71, 0.28, 0.03),
                    s,
                );
                l.y -= 4.0;
            }
            Block::Status(s) => {
                l.ensure(30.0);
                l.y -= 6.0;
                l.rect(MARGIN, l.y - 22.0, 4.0, 24.0, ACCENT);
                l.y -= 4.0;
                l.lines(MARGIN + 12.0, CONTENT_W - 12.0, Font::Bold, 14.0, INK, s);
                l.y -= 6.0;
            }
            Block::Mono(s) => {
                l.lines(MARGIN, CONTENT_W, Font::Mono, 8.0, INK, s);
            }
            Block::Bullet(s) => {
                let lead = 9.5 * 1.35;
                let lines = wrap(s, Font::Regular, 9.5, CONTENT_W - 14.0);
                for (i, line) in lines.iter().enumerate() {
                    l.ensure(lead);
                    l.y -= lead;
                    if i == 0 {
                        l.text(MARGIN + 2.0, l.y, Font::Regular, 9.5, INK, "\u{2022}");
                    }
                    l.text(MARGIN + 14.0, l.y, Font::Regular, 9.5, INK, line);
                }
            }
            Block::Kv(rows) => {
                l.y -= 2.0;
                l.kv(MARGIN, CONTENT_W, rows);
            }
            Block::Finding { badge, title, rows } => {
                l.ensure(50.0);
                l.y -= 8.0;
                l.lines(
                    MARGIN,
                    CONTENT_W,
                    Font::Bold,
                    10.0,
                    INK,
                    &format!("[{}]  {}", badge, title),
                );
                l.kv(MARGIN + 10.0, CONTENT_W - 10.0, rows);
            }
            Block::Space(h) => l.y -= h,
            Block::Grid {
                header,
                widths,
                rows,
                row_h,
            } => {
                const SIZE: f32 = 7.5;
                let lead = SIZE * 1.3;
                let wrapped: Vec<Vec<String>> = header
                    .iter()
                    .zip(widths)
                    .map(|(h, w)| wrap(h, Font::Regular, SIZE, w - 6.0))
                    .collect();
                let head_h = wrapped.iter().map(|w| w.len()).max().unwrap_or(1) as f32 * lead + 6.0;
                l.ensure(head_h + row_h * (*rows).min(3) as f32);
                let draw_row = |l: &mut Layout, h: f32, cells: Option<&Vec<Vec<String>>>| {
                    let top = l.y;
                    let mut x = MARGIN;
                    for (i, w) in widths.iter().enumerate() {
                        let _ = writeln!(
                            l.cur,
                            "{:.3} {:.3} {:.3} RG 0.5 w {:.2} {:.2} {:.2} {:.2} re S",
                            MUTED.0,
                            MUTED.1,
                            MUTED.2,
                            x,
                            top - h,
                            w,
                            h
                        );
                        if let Some(c) = cells {
                            for (j, line) in c[i].iter().enumerate() {
                                l.text(
                                    x + 3.0,
                                    top - lead * (j as f32 + 1.0),
                                    Font::Regular,
                                    SIZE,
                                    MUTED,
                                    line,
                                );
                            }
                        }
                        x += w;
                    }
                    l.y = top - h;
                };
                draw_row(&mut l, head_h, Some(&wrapped));
                for _ in 0..*rows {
                    l.ensure(*row_h);
                    draw_row(&mut l, *row_h, None);
                }
                l.y -= 6.0;
            }
            Block::SignLines(labels) => {
                l.ensure(60.0);
                l.y -= 44.0;
                let w = (CONTENT_W - 20.0 * (labels.len() as f32 - 1.0)) / labels.len() as f32;
                for (i, lab) in labels.iter().enumerate() {
                    let x = MARGIN + i as f32 * (w + 20.0);
                    let _ = writeln!(
                        l.cur,
                        "{:.3} {:.3} {:.3} RG 0.6 w {:.2} {:.2} m {:.2} {:.2} l S",
                        INK.0,
                        INK.1,
                        INK.2,
                        x,
                        l.y,
                        x + w,
                        l.y
                    );
                    for (j, line) in wrap(lab, Font::Regular, 8.0, w).iter().enumerate() {
                        l.text(
                            x,
                            l.y - 11.0 - 10.0 * j as f32,
                            Font::Regular,
                            8.0,
                            MUTED,
                            line,
                        );
                    }
                }
                l.y -= 30.0;
            }
        }
    }
    l.pages.push(l.cur);
    let total = l.pages.len();

    // Assemble objects: 1 catalog, 2 pages, 3-5 fonts, 6 info, then (page, content) pairs.
    let mut objects: Vec<String> = Vec::new();
    let kids: Vec<String> = (0..total).map(|i| format!("{} 0 R", 7 + 2 * i)).collect();
    let (sig_obj, widget_obj) = (7 + 2 * total, 8 + 2 * total);
    if sign.is_some() {
        objects.push(format!(
            "<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [{} 0 R] /SigFlags 3 >> >>",
            widget_obj
        ));
    } else {
        objects.push("<< /Type /Catalog /Pages 2 0 R >>".into());
    }
    objects.push(format!(
        "<< /Type /Pages /Kids [{}] /Count {} >>",
        kids.join(" "),
        total
    ));
    for name in ["Helvetica", "Helvetica-Bold", "Courier"] {
        objects.push(format!(
            "<< /Type /Font /Subtype /Type1 /BaseFont /{} /Encoding /WinAnsiEncoding >>",
            name
        ));
    }
    let date = chrono::Utc::now().format("D:%Y%m%d%H%M%SZ").to_string();
    objects.push(format!(
        "<< /Title {} /Producer {} /Creator {} /CreationDate ({}) >>",
        pdf_string(title),
        pdf_string(producer),
        pdf_string(producer),
        date
    ));
    for (i, content) in l.pages.iter().enumerate() {
        let mut c = band(meta);
        c.push_str(content);
        let foot = format!(
            "{}  \u{2014}  {} {} {} {}",
            footer,
            page_word,
            i + 1,
            of_word,
            total
        );
        let _ = writeln!(
            c,
            "{:.3} {:.3} {:.3} RG 0.6 w {} {} m {} {} l S",
            LINE.0,
            LINE.1,
            LINE.2,
            MARGIN,
            44,
            PAGE_W - MARGIN,
            44
        );
        let _ = writeln!(
            c,
            "{:.3} {:.3} {:.3} rg BT /F1 7.5 Tf {} 32 Td {} Tj ET",
            MUTED.0,
            MUTED.1,
            MUTED.2,
            MARGIN,
            pdf_string(&foot)
        );
        let _ = writeln!(
            c,
            "{:.3} {:.3} {:.3} rg BT /F1 6.8 Tf {} 22 Td {} Tj ET",
            MUTED.0,
            MUTED.1,
            MUTED.2,
            MARGIN,
            pdf_string(meta.tagline)
        );
        let annots = if sign.is_some() && i == 0 {
            format!(" /Annots [{} 0 R]", widget_obj)
        } else {
            String::new()
        };
        objects.push(format!("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {} {}] /Resources << /Font << /F1 3 0 R /F2 4 0 R /F3 5 0 R >> >> /Contents {} 0 R{} >>", PAGE_W, PAGE_H, 8 + 2 * i, annots));
        objects.push(format!("<< /Length {} >>\nstream\n{}endstream", c.len(), c));
    }

    if sign.is_some() {
        objects.push(format!(
            "<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /adbe.pkcs7.detached /ByteRange [0 0000000000 0000000000 0000000000] /Contents <{}> /M ({}) /Reason {} >>",
            "0".repeat(SIG_CONTENTS_BYTES * 2),
            date,
            pdf_string(title)
        ));
        objects.push(format!(
            "<< /Type /Annot /Subtype /Widget /FT /Sig /T (RakvorExaminerSignature) /V {} 0 R /Rect [0 0 0 0] /F 132 /P 7 0 R >>",
            sig_obj
        ));
    }
    let mut out: Vec<u8> = b"%PDF-1.4\n%\xE2\xE3\xCF\xD3\n".to_vec();
    let mut offsets = Vec::with_capacity(objects.len());
    for (i, o) in objects.iter().enumerate() {
        offsets.push(out.len());
        out.extend_from_slice(format!("{} 0 obj\n{}\nendobj\n", i + 1, o).as_bytes());
    }
    let xref = out.len();
    // Where the signature dictionary was written: the placeholder is searched for there only, never in
    // page text that might contain the same bytes.
    let sig_offset = offsets.get(sig_obj - 1).copied().unwrap_or(0);
    let mut x = format!("xref\n0 {}\n0000000000 65535 f \n", objects.len() + 1);
    for off in offsets {
        let _ = writeln!(x, "{:010} 00000 n ", off);
    }
    let _ = write!(
        x,
        "trailer\n<< /Size {} /Root 1 0 R /Info 6 0 R >>\nstartxref\n{}\n%%EOF\n",
        objects.len() + 1,
        xref
    );
    out.extend_from_slice(x.as_bytes());
    if let Some(sign) = sign {
        sign_in_place(&mut out, sig_offset, sign)?;
    }
    Ok(out)
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Fills /ByteRange and /Contents of the signature placeholder (no incremental update needed:
/// the placeholder was written with the document). `sig_offset` is the offset of the signature
/// dictionary object (`N 0 obj`): both placeholders are located inside that object, so text in a page
/// that happens to contain "/Contents <0000" or the byte-range marker is never touched.
fn sign_in_place(out: &mut [u8], sig_offset: usize, sign: SignFn) -> Result<(), String> {
    let obj_end =
        sig_offset + find(&out[sig_offset..], b"endobj").ok_or("signature object not found")?;
    let in_sig = |needle: &[u8]| -> Option<usize> {
        find(&out[sig_offset..obj_end], needle).map(|p| sig_offset + p)
    };
    let start =
        in_sig(b"/Contents <0000").ok_or("signature placeholder missing")? + "/Contents ".len();
    let end = start + 2 + SIG_CONTENTS_BYTES * 2;
    let br_marker = b"/ByteRange [0 0000000000 0000000000 0000000000]";
    let br = in_sig(br_marker).ok_or("byte range placeholder missing")?;
    if !(out.get(start) == Some(&b'<') && out.get(end - 1) == Some(&b'>')) {
        return Err("signature placeholder has an unexpected size".into());
    }
    let range = format!(
        "/ByteRange [0 {:010} {:010} {:010}]",
        start,
        end,
        out.len() - end
    );
    out[br..br + br_marker.len()].copy_from_slice(range.as_bytes());
    let mut signed = Vec::with_capacity(out.len());
    signed.extend_from_slice(&out[..start]);
    signed.extend_from_slice(&out[end..]);
    let der = sign(&signed)?;
    if der.len() > SIG_CONTENTS_BYTES {
        return Err(format!("signature too large ({} bytes)", der.len()));
    }
    let hex = crate::hash::hex(&der).to_uppercase();
    out[start + 1..start + 1 + hex.len()].copy_from_slice(hex.as_bytes());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn produces_a_wellformed_multi_page_pdf() {
        let mut blocks = vec![Block::Title("Informe técnico — señal «ça»".into())];
        for i in 0..120 {
            blocks.push(Block::Kv(vec![(
                format!("Clé {}", i),
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".into(),
            )]));
        }
        let pdf = render(&blocks, &test_meta(), None).unwrap();
        assert!(pdf.starts_with(b"%PDF-1.4"));
        assert!(pdf.ends_with(b"%%EOF\n"));
        let text = String::from_utf8_lossy(&pdf);
        assert!(
            text.contains("/Count 3") || text.contains("/Count 4"),
            "multi-page"
        );
        assert!(text.contains("\\351"), "é encoded as WinAnsi octal");
    }

    fn test_meta() -> Meta<'static> {
        Meta {
            title: "t",
            footer: "foot",
            page_word: "Page",
            of_word: "of",
            producer: "test",
            descriptor: "FORENSICS",
            tagline: "We uncover the hidden.",
        }
    }

    #[test]
    fn signature_placeholder_is_filled_and_byte_range_covers_the_rest() {
        let sign = |data: &[u8]| -> Result<Vec<u8>, String> {
            Ok(crate::hash::hash_bytes(data, crate::hash::HashAlgo::Sha256).into_bytes())
        };
        let pdf = render(
            &[
                Block::Para("x".into()),
                Block::Grid {
                    header: vec!["a".into(), "b".into()],
                    widths: vec![100.0, 100.0],
                    rows: 3,
                    row_h: 20.0,
                },
                Block::SignLines(vec!["Examiner".into(), "Receiver".into()]),
            ],
            &test_meta(),
            Some(&sign),
        )
        .unwrap();
        let text = String::from_utf8_lossy(&pdf);
        assert!(text.contains("/SigFlags 3") && !text.contains("/ByteRange [0 0000000000"));
        let sig = find(&pdf, b"/Type /Sig ").unwrap();
        let start = sig + find(&pdf[sig..], b"/Contents <").unwrap() + 10;
        let end = start + 2 + SIG_CONTENTS_BYTES * 2;
        let mut covered = pdf[..start].to_vec();
        covered.extend_from_slice(&pdf[end..]);
        let expected = crate::hash::hex(
            &crate::hash::hash_bytes(&covered, crate::hash::HashAlgo::Sha256).into_bytes(),
        )
        .to_uppercase();
        assert!(text.contains(&format!("<{}", expected)));
        assert!(pdf.ends_with(b"%%EOF\n"));
    }

    /// Page text holding the placeholder byte sequences must not be mistaken for the signature dictionary.
    #[test]
    fn placeholder_bytes_in_page_text_are_left_alone() {
        let sign = |data: &[u8]| -> Result<Vec<u8>, String> {
            Ok(crate::hash::hash_bytes(data, crate::hash::HashAlgo::Sha256).into_bytes())
        };
        let decoy = "/Contents <0000 and /ByteRange [0 0000000000 0000000000 0000000000]";
        let pdf = render(
            &[Block::Title(decoy.into()), Block::Para(decoy.into())],
            &test_meta(),
            Some(&sign),
        )
        .unwrap();
        let sig = find(&pdf, b"/Type /Sig ").unwrap();
        // The decoys come before the signature object and are unchanged.
        let first_decoy = find(&pdf, b"/Contents <0000 and").unwrap();
        assert!(first_decoy < sig);
        assert!(
            find(
                &pdf[..sig],
                b"/ByteRange [0 0000000000 0000000000 0000000000]"
            )
            .is_some()
        );
        // The real placeholder (inside the signature object) holds the signature over the byte range.
        let br_at = sig + find(&pdf[sig..], b"/ByteRange [").unwrap();
        let br: Vec<usize> = String::from_utf8_lossy(&pdf[br_at + 12..br_at + 12 + 34])
            .split_whitespace()
            .map(|x| x.parse().unwrap())
            .collect();
        assert_eq!(br[0], 0);
        assert_eq!(br[2] + br[3], pdf.len());
        assert!(
            br[1] > sig,
            "the signed gap is inside the signature dictionary"
        );
        let mut covered = pdf[..br[1]].to_vec();
        covered.extend_from_slice(&pdf[br[2]..]);
        let expected = crate::hash::hex(
            &crate::hash::hash_bytes(&covered, crate::hash::HashAlgo::Sha256).into_bytes(),
        )
        .to_uppercase();
        assert_eq!(
            &pdf[br[1] + 1..br[1] + 1 + expected.len()],
            expected.as_bytes()
        );
    }

    #[test]
    fn wrapping_breaks_long_tokens() {
        let lines = wrap(&"a".repeat(400), Font::Mono, 8.0, 100.0);
        assert!(
            lines.len() > 1
                && lines
                    .iter()
                    .all(|l| text_width(l, Font::Mono, 8.0) <= 100.0)
        );
    }
}
