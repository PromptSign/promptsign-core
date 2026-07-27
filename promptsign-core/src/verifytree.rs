// Discover and verify every signable instruction artifact under given roots:
// bundle directories (.promptsign/bundle.json), sidecar-signed files
// (*.psig.json), and well-known instruction files that SHOULD be signed.

use crate::verify::{verify_target, VerifyOptions, VerifyResult};
use crate::Result;
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf, MAIN_SEPARATOR};

const SKIP_DIRS: [&str; 5] = [
    ".git",
    "node_modules",
    "__pycache__",
    ".venv",
    ".promptsign",
];
const KNOWN_FILES: [&str; 10] = [
    "CLAUDE.md",
    "AGENTS.md",
    "SKILL.md",
    // OpenClaw workspace bootstrap files (also loaded by ClawPilot desktop apps).
    "SOUL.md",
    "TOOLS.md",
    "IDENTITY.md",
    "USER.md",
    "HEARTBEAT.md",
    "BOOTSTRAP.md",
    "MEMORY.md",
];

fn has_sidecar(abs: &Path) -> bool {
    let mut s = abs.as_os_str().to_owned();

    s.push(".psig.json");
    PathBuf::from(s).exists()
}

fn walk(dir: &Path, bundle_dirs: &mut Vec<PathBuf>, files: &mut Vec<PathBuf>) {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    if dir.join(".promptsign").join("bundle.json").exists() {
        bundle_dirs.push(dir.to_path_buf());
    }
    for ent in entries.flatten() {
        let name = ent.file_name().to_string_lossy().into_owned();
        let abs = dir.join(&name);
        let ftype = match ent.file_type() {
            Ok(t) => t,
            Err(_) => continue,
        };

        if ftype.is_dir() {
            if !SKIP_DIRS.contains(&name.as_str()) {
                walk(&abs, bundle_dirs, files);
            }
        } else if ftype.is_file() {
            let in_agents_dir = dir.file_name().is_some_and(|d| d == "agents")
                && name.to_lowercase().ends_with(".md");

            if KNOWN_FILES.contains(&name.as_str()) || in_agents_dir || has_sidecar(&abs) {
                files.push(abs);
            }
        }
    }
}

pub fn discover_targets(roots: &[String]) -> Vec<PathBuf> {
    let mut bundle_dirs: Vec<PathBuf> = Vec::new();
    let mut files: Vec<PathBuf> = Vec::new();

    for root in roots {
        let abs = match std::path::absolute(root) {
            Ok(p) => p,
            Err(_) => continue,
        };

        if !abs.exists() {
            continue;
        }
        if abs.is_file() {
            files.push(abs);
        } else {
            walk(&abs, &mut bundle_dirs, &mut files);
        }
    }

    let mut seen: HashSet<PathBuf> = HashSet::new();
    let mut targets: Vec<PathBuf> = Vec::new();

    for d in &bundle_dirs {
        if seen.insert(d.clone()) {
            targets.push(d.clone());
        }
    }

    let covered = |f: &Path| {
        let fs_str = f.to_string_lossy();

        bundle_dirs
            .iter()
            .any(|d| fs_str.starts_with(&format!("{}{}", d.to_string_lossy(), MAIN_SEPARATOR)))
    };

    for f in files {
        if seen.contains(&f) || covered(&f) {
            continue;
        }
        seen.insert(f.clone());
        targets.push(f);
    }
    targets
}

pub fn verify_tree(roots: &[String], opts: &VerifyOptions) -> Result<Vec<VerifyResult>> {
    discover_targets(roots)
        .iter()
        .map(|t| verify_target(&t.to_string_lossy(), opts))
        .collect()
}
