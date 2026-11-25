//! Driver for the module doc generator (`#964`).
//!
//! Regenerates `docs/generated/<module>.md` from backend source. The CI
//! `docs-drift-check` step runs this with `--check` into a scratch location
//! and diffs against the committed file so docs can never silently fall out
//! of sync with the code.
//!
//! Usage:
//!   cargo run --package ethos-protocol-backend --bin doc_generator -- \
//!     --module feature_flags --output docs/generated/feature_flags.md

use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use ethos_protocol_backend::doc_generator::generate;

fn main() -> ExitCode {
    let mut module: Option<String> = None;
    let mut output: Option<PathBuf> = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--module" => module = args.next(),
            "--output" => output = args.next().map(PathBuf::from),
            "--help" | "-h" => {
                eprintln!("usage: doc_generator --module <name> --output <path>");
                return ExitCode::SUCCESS;
            }
            other => {
                eprintln!("unknown argument: {other}");
                return ExitCode::from(2);
            }
        }
    }

    let module = match module {
        Some(m) => m,
        None => {
            eprintln!("--module is required");
            return ExitCode::from(2);
        }
    };
    let output = match output {
        Some(o) => o,
        None => {
            eprintln!("--output is required");
            return ExitCode::from(2);
        }
    };

    let source_path = PathBuf::from(format!("backend/src/{module}.rs"));
    let source = match fs::read_to_string(&source_path) {
        Ok(s) => s,
        Err(err) => {
            eprintln!("failed to read {}: {err}", source_path.display());
            return ExitCode::from(1);
        }
    };
    let markdown = generate(&module, &source, Some(&source));

    if let Some(parent) = output.parent() {
        if !parent.as_os_str().is_empty() {
            if let Err(err) = fs::create_dir_all(parent) {
                eprintln!("failed to create {}: {err}", parent.display());
                return ExitCode::from(1);
            }
        }
    }
    if let Err(err) = fs::write(&output, markdown) {
        eprintln!("failed to write {}: {err}", output.display());
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}
