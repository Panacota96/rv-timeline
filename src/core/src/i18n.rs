//! Report wording in English, Spanish and French. The catalogues live in `i18n/*.json`
//! (shared with the Python profile) and are compiled into the binary.

use serde_json::Value;
use std::collections::BTreeMap;
use std::sync::OnceLock;

pub const LANGS: [&str; 3] = ["en", "es", "fr"];

const SOURCES: [(&str, &str); 3] = [
    ("en", include_str!("../../../i18n/en.json")),
    ("es", include_str!("../../../i18n/es.json")),
    ("fr", include_str!("../../../i18n/fr.json")),
];

pub struct Catalog {
    pub lang: &'static str,
    data: Value,
}

fn catalogs() -> &'static Vec<Catalog> {
    static C: OnceLock<Vec<Catalog>> = OnceLock::new();
    C.get_or_init(|| {
        SOURCES
            .iter()
            .map(|(l, s)| Catalog {
                lang: l,
                data: serde_json::from_str(s).expect("valid i18n JSON"),
            })
            .collect()
    })
}

/// `"en"`, `"es"`, `"fr"` or `"all"` (comma-separated lists allowed).
pub fn parse_langs(s: &str) -> Result<Vec<String>, String> {
    let mut out: Vec<String> = Vec::new();
    for part in s
        .split(',')
        .map(|p| p.trim().to_ascii_lowercase())
        .filter(|p| !p.is_empty())
    {
        if part == "all" {
            return Ok(LANGS.iter().map(|l| l.to_string()).collect());
        }
        if !LANGS.contains(&part.as_str()) {
            return Err(format!(
                "unsupported language '{}': use en, es, fr or all",
                part
            ));
        }
        if !out.contains(&part) {
            out.push(part);
        }
    }
    if out.is_empty() {
        return Err("no language given: use en, es, fr or all".into());
    }
    Ok(out)
}

pub fn catalog(lang: &str) -> &'static Catalog {
    catalogs()
        .iter()
        .find(|c| c.lang == lang)
        .unwrap_or(&catalogs()[0])
}

/// Replaces `%{name}` placeholders.
pub fn fill(template: &str, params: &BTreeMap<String, String>) -> String {
    let mut s = template.to_string();
    for (k, v) in params {
        s = s.replace(&format!("%{{{}}}", k), v);
    }
    s
}

impl Catalog {
    pub fn labels(&self) -> &Value {
        &self.data["labels"]
    }

    pub fn brand(&self) -> &Value {
        &self.data["brand"]
    }

    pub fn custody(&self) -> &Value {
        &self.data["custody"]
    }

    /// GUI wording.
    pub fn ui(&self, key: &str) -> String {
        self.data["ui"][key].as_str().unwrap_or(key).to_string()
    }

    pub fn label(&self, key: &str) -> String {
        self.data["labels"][key].as_str().unwrap_or(key).to_string()
    }

    pub fn severity(&self, key: &str) -> String {
        self.data["severity"][key]
            .as_str()
            .unwrap_or(key)
            .to_string()
    }

    /// (title, shows, does_not_prove) for a finding code.
    pub fn finding(
        &self,
        code: &str,
        params: &BTreeMap<String, String>,
    ) -> (String, String, String) {
        let f = &self.data["findings"][code];
        let get = |k: &str| fill(f[k].as_str().unwrap_or(code), params);
        (get("title"), get("shows"), get("does_not_prove"))
    }

    pub fn limitation(&self, code: &str) -> String {
        self.data["limitations"][code]
            .as_str()
            .unwrap_or(code)
            .to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalogues_have_the_same_keys() {
        fn keys(v: &Value, prefix: &str, out: &mut Vec<String>) {
            if let Some(o) = v.as_object() {
                for (k, v) in o {
                    keys(v, &format!("{}.{}", prefix, k), out);
                }
            } else {
                out.push(prefix.to_string());
            }
        }
        let mut reference = Vec::new();
        keys(&catalog("en").data, "", &mut reference);
        for l in ["es", "fr"] {
            let mut k = Vec::new();
            keys(&catalog(l).data, "", &mut k);
            assert_eq!(reference, k, "{} differs from en", l);
        }
    }

    #[test]
    fn langs_and_placeholders() {
        assert_eq!(parse_langs("all").unwrap().len(), 3);
        assert_eq!(parse_langs("es,fr,es").unwrap(), vec!["es", "fr"]);
        assert!(parse_langs("de").is_err());
        let mut p = BTreeMap::new();
        p.insert("extension".to_string(), "jpg".to_string());
        p.insert("detected".to_string(), "PDF document".to_string());
        let (_, shows, _) = catalog("es").finding("EXTENSION_MISMATCH", &p);
        assert!(
            shows.contains(".jpg") && shows.contains("PDF document"),
            "{}",
            shows
        );
        assert_ne!(
            catalog("fr").label("title_summary"),
            catalog("en").label("title_summary")
        );
    }
}
