//! Command-line arguments of the GUI executable: input paths (files dropped on the .exe icon) and
//! `--case-dir DIR` / `--case-dir=DIR`, which RV Hub passes to open the tool on a case folder.

use std::ffi::OsString;
use std::path::PathBuf;

/// The option RV Hub uses to preset the case folder.
pub const CASE_DIR_FLAG: &str = "--case-dir";

/// What the GUI was started with.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct LaunchArgs {
    /// `--case-dir` value (the last one wins when repeated).
    pub case_dir: Option<PathBuf>,
    /// Every other argument, in order: files or folders to pre-load.
    pub inputs: Vec<PathBuf>,
    /// Problems with the arguments (ignored, shown to the user and recorded in the audit log).
    pub notes: Vec<String>,
}

/// Splits the GUI arguments (without the program name, and without a leading `worker`, which `main`
/// handles first). `--case-dir` without a value (last argument, empty, or followed by another `--`
/// option) is ignored with a note; it is never taken as an input path.
pub fn parse_launch_args(args: impl IntoIterator<Item = OsString>) -> LaunchArgs {
    let mut out = LaunchArgs::default();
    let mut it = args.into_iter().peekable();
    while let Some(arg) = it.next() {
        let text = arg.to_string_lossy();
        let value = if text == CASE_DIR_FLAG {
            match it.peek() {
                Some(next) if next.to_string_lossy().starts_with("--") => None,
                // An empty value is consumed (it is not an input either).
                Some(_) => it.next().filter(|v| !v.is_empty()),
                None => None,
            }
        } else if let Some(v) = text.strip_prefix("--case-dir=") {
            Some(OsString::from(v)).filter(|v| !v.is_empty())
        } else {
            out.inputs.push(PathBuf::from(arg));
            continue;
        };
        match value {
            Some(v) => out.case_dir = Some(PathBuf::from(v)),
            None => out
                .notes
                .push(format!("{} given without a folder: ignored", CASE_DIR_FLAG)),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> LaunchArgs {
        parse_launch_args(args.iter().map(OsString::from))
    }

    #[test]
    fn case_dir_then_inputs() {
        let a = parse(&["--case-dir", "X", "a.pdf"]);
        assert_eq!(a.case_dir, Some(PathBuf::from("X")));
        assert_eq!(a.inputs, vec![PathBuf::from("a.pdf")]);
        assert!(a.notes.is_empty());
    }

    #[test]
    fn case_dir_with_equals_sign() {
        let a = parse(&["--case-dir=X"]);
        assert_eq!(a.case_dir, Some(PathBuf::from("X")));
        assert!(a.inputs.is_empty() && a.notes.is_empty());
        let a = parse(&["b.pdf", "--case-dir=E:\\CASE 014"]);
        assert_eq!(a.case_dir, Some(PathBuf::from("E:\\CASE 014")));
        assert_eq!(a.inputs, vec![PathBuf::from("b.pdf")]);
    }

    #[test]
    fn without_the_flag_every_argument_is_an_input() {
        let a = parse(&["a.pdf", "D:\\evidence"]);
        assert_eq!(a.case_dir, None);
        assert_eq!(
            a.inputs,
            vec![PathBuf::from("a.pdf"), PathBuf::from("D:\\evidence")]
        );
        assert!(a.notes.is_empty());
        assert_eq!(parse(&[]), LaunchArgs::default());
    }

    #[test]
    fn flag_without_a_value_is_ignored_with_a_note() {
        for args in [
            &["a.pdf", "--case-dir"][..],
            &["--case-dir=", "a.pdf"][..],
            &["--case-dir", "", "a.pdf"][..],
        ] {
            let a = parse(args);
            assert_eq!(a.case_dir, None, "{:?}", args);
            assert_eq!(a.inputs, vec![PathBuf::from("a.pdf")], "{:?}", args);
            assert_eq!(a.notes.len(), 1, "{:?}", args);
            assert!(a.notes[0].contains("--case-dir"));
        }
        // Followed by another option: the option is not swallowed as the folder.
        let a = parse(&["--case-dir", "--case-dir=Y"]);
        assert_eq!(a.case_dir, Some(PathBuf::from("Y")));
        assert_eq!(a.notes.len(), 1);
    }

    #[test]
    fn last_case_dir_wins() {
        let a = parse(&["--case-dir", "X", "--case-dir", "Y"]);
        assert_eq!(a.case_dir, Some(PathBuf::from("Y")));
    }
}
