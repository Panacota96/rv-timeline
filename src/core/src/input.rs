//! Turns user input (files, folders, list files) into a sorted, de-duplicated list of evidence items.
//!
//! Item order (shared with the Python profile, so both number the same input identically): every path is
//! made absolute and lexically normalised (`case::normalize_path`), duplicates are dropped, and the items
//! are sorted by that string, bytewise (UTF-8). Item 1 is the smallest path.

use crate::case::normalize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, PartialEq)]
pub struct Item {
    pub index: u64,
    pub path: PathBuf,
    pub size: u64,
}

/// Paths listed in an `--input-list` file: one per line, `#` comments and blank lines ignored, a UTF-8 byte
/// order mark (Notepad) stripped, relative paths resolved from the list file's folder.
pub fn read_list(list: &Path) -> Result<Vec<PathBuf>, String> {
    let text = std::fs::read_to_string(list)
        .map_err(|e| format!("cannot read list file {}: {}", list.display(), e))?;
    let text = text.strip_prefix('\u{feff}').unwrap_or(&text);
    let base = list.parent().unwrap_or(Path::new("."));
    Ok(text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|line| {
            let p = PathBuf::from(line);
            if p.is_absolute() { p } else { base.join(p) }
        })
        .collect())
}

/// `inputs`: files or folders. `list_file`: a text file with one path per line (# comments allowed).
/// Folders are read one level deep unless `recursive`. Symbolic links are not followed.
pub fn collect(
    inputs: &[PathBuf],
    list_file: Option<&Path>,
    recursive: bool,
) -> Result<Vec<Item>, String> {
    let mut paths: Vec<PathBuf> = inputs.to_vec();
    if let Some(list) = list_file {
        paths.extend(read_list(list)?);
    }
    if paths.is_empty() {
        return Err("no input given: use --input FILE|FOLDER or --input-list FILE".into());
    }
    // Key: the normalised path string (sort order and de-duplication); value: the path to open.
    let mut files: BTreeMap<String, PathBuf> = BTreeMap::new();
    let mut add = |p: PathBuf| {
        let n = normalize(&p);
        files.entry(n.display().to_string()).or_insert(n);
    };
    for p in &paths {
        let meta = std::fs::symlink_metadata(p)
            .map_err(|e| format!("cannot access {}: {}", p.display(), e))?;
        if meta.is_file() {
            add(p.clone());
        } else if meta.is_dir() {
            let walker = walkdir::WalkDir::new(p)
                .follow_links(false)
                .max_depth(if recursive { usize::MAX } else { 1 });
            for entry in walker {
                let entry =
                    entry.map_err(|e| format!("cannot read folder {}: {}", p.display(), e))?;
                if entry.file_type().is_file() {
                    add(entry.into_path());
                }
            }
        } else {
            return Err(format!(
                "{} is neither a file nor a folder (symbolic links are not followed)",
                p.display()
            ));
        }
    }
    // BTreeMap<String, _> iterates in bytewise (UTF-8) order of the keys.
    Ok(files
        .into_values()
        .enumerate()
        .map(|(i, path)| {
            let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
            Item {
                index: i as u64 + 1,
                path,
                size,
            }
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn files_folders_lists_and_recursion() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("b.txt"), "b").unwrap();
        std::fs::write(d.path().join("a.txt"), "a").unwrap();
        std::fs::create_dir(d.path().join("sub")).unwrap();
        std::fs::write(d.path().join("sub/c.txt"), "c").unwrap();
        std::fs::write(
            d.path().join("list.txt"),
            "# evidence\na.txt\n\nsub/c.txt\n",
        )
        .unwrap();

        let flat = collect(&[d.path().to_path_buf()], None, false).unwrap();
        assert_eq!(flat.len(), 3); // a, b, list.txt
        assert_eq!(flat[0].path.file_name().unwrap(), "a.txt");
        assert_eq!(flat[0].index, 1);

        let deep = collect(&[d.path().to_path_buf()], None, true).unwrap();
        assert_eq!(deep.len(), 4);

        let listed = collect(&[], Some(&d.path().join("list.txt")), false).unwrap();
        assert_eq!(listed.len(), 2);

        assert!(collect(&[], None, false).is_err());
        assert!(collect(&[d.path().join("missing")], None, false).is_err());
    }

    /// Bytewise order of the whole normalised path, not component order: "a-b/x" sorts before "a/x"
    /// ('-' 0x2D < '/' 0x2F), and "B" before "a" (no case folding). The same folder is numbered
    /// identically by the Python profile (tests/test_core.py::test_item_order_is_bytewise_path_order).
    #[test]
    fn items_are_sorted_by_normalised_path_bytes() {
        let d = tempfile::tempdir().unwrap();
        for f in [
            "a/x.txt",
            "a-b/x.txt",
            "B.txt",
            "a.txt",
            "é.txt",
            "z/y/../w.txt",
        ] {
            let p = d.path().join(f);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, f).unwrap();
        }
        let dot = d.path().join("a").join("..").join("a.txt"); // same file as a.txt, not a duplicate item
        let items = collect(&[d.path().to_path_buf(), dot], None, true).unwrap();
        let names: Vec<String> = items
            .iter()
            .map(|i| {
                i.path
                    .strip_prefix(d.path())
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/")
            })
            .collect();
        let mut keys: Vec<String> = items.iter().map(|i| i.path.display().to_string()).collect();
        let sorted = {
            let mut k = keys.clone();
            k.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
            k
        };
        assert_eq!(keys, sorted);
        keys.dedup();
        assert_eq!(keys.len(), items.len());
        if cfg!(not(windows)) {
            assert_eq!(
                names,
                ["B.txt", "a-b/x.txt", "a.txt", "a/x.txt", "z/w.txt", "é.txt"]
            );
        }
    }

    #[test]
    fn list_file_with_utf8_bom_is_read() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("a.txt"), "a").unwrap();
        std::fs::write(d.path().join("list.txt"), "\u{feff}a.txt\r\n# comment\r\n").unwrap();
        let items = collect(&[], Some(&d.path().join("list.txt")), false).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].path.file_name().unwrap(), "a.txt");
    }
}
