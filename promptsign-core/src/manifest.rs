// Bundle manifest construction and integrity re-verification.
// The manifest — not any individual file — is the unit of signing (spec/01-manifest.md).

use crate::canonicalize::{digest_file, is_markdown};
use crate::Result;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

pub const MANIFEST_SCHEMA: &str = "promptsign/manifest/v1";

const SKIP_DIRS: [&str; 5] = [
    ".promptsign",
    ".git",
    "node_modules",
    "__pycache__",
    ".venv",
];
const EXEC_EXTS: [&str; 16] = [
    ".py", ".sh", ".bash", ".zsh", ".js", ".mjs", ".cjs", ".ts", ".ps1", ".psm1", ".cmd", ".bat",
    ".exe", ".rb", ".pl", ".php",
];
const ENTRYPOINTS: [&str; 10] = [
    "SKILL.md",
    "CLAUDE.md",
    "AGENTS.md",
    // OpenClaw workspace bootstrap files (also loaded by ClawPilot desktop apps).
    "SOUL.md",
    "TOOLS.md",
    "IDENTITY.md",
    "USER.md",
    "HEARTBEAT.md",
    "BOOTSTRAP.md",
    "MEMORY.md",
];
/// Files an agent injects into model context verbatim (whole-file), as opposed
/// to structured-frontmatter files like SKILL.md where the loader surfaces only
/// known keys. Embedded `x-promptsign:` signatures are refused for these on
/// sign, and their mere presence is a verification failure on verify — a pasted
/// marker must never masquerade as a signature (see spec/03-bundle.md).
/// Covers Claude Code / Codex (CLAUDE.md, AGENTS.md) and the OpenClaw workspace
/// bootstrap set. Some names are generic (USER.md, MEMORY.md); the refusal is
/// deliberately broad — a sidecar signature always remains available.
pub const CONTEXT_INJECTED: [&str; 9] = [
    "CLAUDE.md",
    "AGENTS.md",
    "SOUL.md",
    "TOOLS.md",
    "IDENTITY.md",
    "USER.md",
    "HEARTBEAT.md",
    "BOOTSTRAP.md",
    "MEMORY.md",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEntry {
    pub path: String,
    pub sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub schema: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created: Option<String>,
    pub files: Vec<FileEntry>,
}

pub fn is_sidecar(name: &str) -> bool {
    name.ends_with(".psig.json")
}

pub fn strip_md_ext(name: &str) -> String {
    let lower = name.to_lowercase();

    for ext in [".markdown", ".md"] {
        if lower.ends_with(ext) {
            return name[..name.len() - ext.len()].to_string();
        }
    }
    name.to_string()
}

pub fn role_for(rel_path: &str) -> &'static str {
    if !rel_path.contains('/') && ENTRYPOINTS.contains(&rel_path) {
        return "entrypoint";
    }

    let base = rel_path.rsplit('/').next().unwrap_or(rel_path);
    let ext = match base.rfind('.') {
        Some(i) if i > 0 => base[i..].to_lowercase(),
        _ => String::new(),
    };

    if EXEC_EXTS.contains(&ext.as_str()) || rel_path.split('/').next() == Some("scripts") {
        return "executable";
    }
    "reference"
}

fn walk(root: &Path, rel: &str, out: &mut Vec<String>) -> Result<()> {
    let abs = if rel.is_empty() {
        root.to_path_buf()
    } else {
        root.join(rel)
    };
    let entries = fs::read_dir(&abs).map_err(|e| format!("{}: {e}", abs.display()))?;

    for ent in entries {
        let ent = ent.map_err(|e| format!("{}: {e}", abs.display()))?;
        let name = ent.file_name().to_string_lossy().into_owned();
        let rel_child = if rel.is_empty() {
            name.clone()
        } else {
            format!("{rel}/{name}")
        };
        let ftype = ent.file_type().map_err(|e| format!("{rel_child}: {e}"))?;

        if ftype.is_dir() {
            if SKIP_DIRS.contains(&name.as_str()) {
                continue;
            }
            walk(root, &rel_child, out)?;
        } else if ftype.is_file() {
            if is_sidecar(&name) {
                continue;
            }
            out.push(rel_child);
        }
    }
    Ok(())
}

pub fn walk_files(root: &Path) -> Result<Vec<String>> {
    let mut out = Vec::new();

    walk(root, "", &mut out)?;
    out.sort();
    Ok(out)
}

// Best-effort read of a top-level `name:` / `version:` from a markdown file's
// YAML frontmatter, so a signed skill/agent carries its real name and version
// instead of the basename and 0.0.0 placeholder. Metadata convenience for the
// default only (an explicit --name/--version wins) — never consulted on verify.
fn frontmatter_field(text: &str, field: &str) -> Option<String> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut lines = text.lines();

    if lines.next()?.trim_end() != "---" {
        return None;
    }
    for line in lines {
        let line = line.trim_end();

        if line == "---" {
            break;
        }
        // Only a top-level key (no indentation) counts.
        if line.starts_with(char::is_whitespace) {
            continue;
        }
        if let Some((key, val)) = line.split_once(':') {
            if key.trim().eq_ignore_ascii_case(field) {
                let v = val.trim().trim_matches(['"', '\'']).trim();

                return (!v.is_empty()).then(|| v.to_string());
            }
        }
    }
    None
}

// The entrypoint whose frontmatter names the artifact: the lone file in file
// scope, or the root SKILL.md / CLAUDE.md / AGENTS.md of a directory.
fn entrypoint_text(root: &Path, scope: &str, rel_paths: &[String]) -> Option<String> {
    let rel = if scope == "file" {
        rel_paths.first()?.clone()
    } else {
        ENTRYPOINTS
            .iter()
            .find(|e| rel_paths.iter().any(|p| p == *e))?
            .to_string()
    };
    let bytes = fs::read(root.join(&rel)).ok()?;
    let end = bytes.len().min(4096);

    Some(String::from_utf8_lossy(&bytes[..end]).into_owned())
}

pub fn infer_kind(rel_paths: &[String]) -> &'static str {
    if rel_paths.iter().any(|p| p == "SKILL.md") {
        return "skill";
    }
    if rel_paths.iter().any(|p| p.starts_with("commands/")) {
        return "command";
    }
    if rel_paths.len() == 1 {
        let base = rel_paths[0].rsplit('/').next().unwrap_or(&rel_paths[0]);

        if CONTEXT_INJECTED.contains(&base) {
            return "instructions";
        }
        if is_markdown(base) {
            return "agent";
        }
    }
    "file"
}

fn file_entry(root: &Path, rel_path: &str) -> Result<FileEntry> {
    let role = role_for(rel_path);
    let buf = fs::read(root.join(rel_path)).map_err(|e| format!("{rel_path}: {e}"))?;
    let sha256 = digest_file(&buf, rel_path, role).map_err(|e| format!("{rel_path}: {e}"))?;

    Ok(FileEntry {
        path: rel_path.to_string(),
        sha256,
        role: Some(role.to_string()),
    })
}

pub struct BuildOptions<'a> {
    pub name: Option<&'a str>,
    pub version: Option<&'a str>,
    pub kind: Option<&'a str>,
}

/// scope "dir": manifest covers an entire bundle directory (extra files = failure).
/// scope "file": manifest covers a single standalone file with a sidecar signature.
pub fn build_manifest(
    root: &Path,
    single_file: Option<&Path>,
    opts: &BuildOptions,
) -> Result<Manifest> {
    let (rel_paths, scope) = match single_file {
        Some(f) => {
            let base = f
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .ok_or_else(|| format!("invalid file path: {}", f.display()))?;

            (vec![base], "file")
        }
        None => {
            let paths = walk_files(root)?;

            if paths.is_empty() {
                return Err(format!("no files to sign under {}", root.display()));
            }
            (paths, "dir")
        }
    };
    let mut files = Vec::with_capacity(rel_paths.len());

    for p in &rel_paths {
        let mut entry = file_entry(root, p)?;

        if scope == "file" && is_markdown(p) {
            entry.role = Some("entrypoint".to_string());
        }
        files.push(entry);
    }

    let fm = entrypoint_text(root, scope, &rel_paths);
    let fm_name = fm.as_deref().and_then(|t| frontmatter_field(t, "name"));
    let fm_version = fm.as_deref().and_then(|t| frontmatter_field(t, "version"));
    let default_name = {
        let base = single_file
            .unwrap_or(root)
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();

        strip_md_ext(&base)
    };

    Ok(Manifest {
        schema: MANIFEST_SCHEMA.to_string(),
        name: opts
            .name
            .map(str::to_string)
            .or(fm_name)
            .unwrap_or(default_name),
        version: Some(
            opts.version
                .map(str::to_string)
                .or(fm_version)
                .unwrap_or_else(|| "0.0.0".to_string()),
        ),
        kind: Some(
            opts.kind
                .map(str::to_string)
                .unwrap_or_else(|| infer_kind(&rel_paths).to_string()),
        ),
        scope: Some(scope.to_string()),
        created: Some(crate::util::iso8601_now()),
        files,
    })
}

/// File-scope integrity: a file-scope manifest describes exactly the target file
/// itself, so verify *that* file's bytes directly instead of resolving the stored
/// basename against the directory. The stored-name resolution used by
/// `check_integrity` would otherwise check a same-named neighbour (masking a
/// tampered copy) or report "missing" after a legitimate rename — the latter
/// defeating the whole point of embedded carriage, which travels with the file.
pub fn check_file_integrity(file: &Path, manifest: &Manifest) -> Result<Vec<String>> {
    let name = file
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let entry = match manifest.files.first() {
        Some(e) => e,
        None => return Ok(vec!["manifest lists no files".to_string()]),
    };
    let role = entry
        .role
        .clone()
        .unwrap_or_else(|| role_for(&name).to_string());
    let buf = match fs::read(file) {
        Ok(b) => b,
        Err(e) => return Ok(vec![format!("{name}: {e}")]),
    };
    let actual = digest_file(&buf, &name, &role).map_err(|e| format!("{name}: {e}"))?;

    if actual != entry.sha256 {
        return Ok(vec![format!("modified: {name}")]);
    }
    Ok(vec![])
}

/// Recompute digests from disk and compare against a verified manifest.
/// Returns a list of problems (empty = intact).
pub fn check_integrity(root: &Path, manifest: &Manifest) -> Result<Vec<String>> {
    let mut problems = Vec::new();

    for entry in &manifest.files {
        let rel_path = &entry.path;

        if rel_path.contains("..") || rel_path.starts_with('/') {
            problems.push(format!("manifest lists suspicious path: {rel_path}"));
            continue;
        }

        let abs = root.join(rel_path);

        if !abs.exists() {
            problems.push(format!("missing file: {rel_path}"));
            continue;
        }
        match file_entry(root, rel_path) {
            Err(e) => problems.push(e),
            Ok(actual) => {
                if actual.sha256 != entry.sha256 {
                    problems.push(format!("modified: {rel_path}"));
                }
            }
        }
    }
    if manifest.scope.as_deref() != Some("file") {
        let listed: std::collections::HashSet<&str> =
            manifest.files.iter().map(|f| f.path.as_str()).collect();

        for on_disk in walk_files(root)? {
            if !listed.contains(on_disk.as_str()) {
                problems.push(format!("unlisted file present: {on_disk}"));
            }
        }
    }
    Ok(problems)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roles() {
        assert_eq!(role_for("SKILL.md"), "entrypoint");
        assert_eq!(role_for("CLAUDE.md"), "entrypoint");
        assert_eq!(role_for("SOUL.md"), "entrypoint");
        assert_eq!(role_for("MEMORY.md"), "entrypoint");
        assert_eq!(role_for("sub/SKILL.md"), "reference");
        assert_eq!(role_for("sub/SOUL.md"), "reference");
        assert_eq!(role_for("scripts/run.py"), "executable");
        assert_eq!(role_for("scripts/notes.txt"), "executable");
        assert_eq!(role_for("tool.PY"), "executable");
        assert_eq!(role_for("references/rules.md"), "reference");
        assert_eq!(role_for(".env"), "reference");
    }

    #[test]
    fn kinds() {
        assert_eq!(
            infer_kind(&["SKILL.md".into(), "scripts/a.py".into()]),
            "skill"
        );
        assert_eq!(infer_kind(&["commands/deploy.md".into()]), "command");
        assert_eq!(
            infer_kind(&["commands/a.md".into(), "commands/b.md".into()]),
            "command"
        );
        // SKILL.md wins over a commands/ subdirectory.
        assert_eq!(
            infer_kind(&["SKILL.md".into(), "commands/x.md".into()]),
            "skill"
        );
        // Only a top-level commands/ segment counts.
        assert_eq!(infer_kind(&["sub/commands/x.md".into()]), "agent");
        assert_eq!(infer_kind(&["CLAUDE.md".into()]), "instructions");
        // OpenClaw workspace bootstrap files are instructions too.
        assert_eq!(infer_kind(&["SOUL.md".into()]), "instructions");
        assert_eq!(infer_kind(&["TOOLS.md".into()]), "instructions");
        assert_eq!(infer_kind(&["reviewer.md".into()]), "agent");
        assert_eq!(infer_kind(&["a.md".into(), "b.md".into()]), "file");
    }

    #[test]
    fn frontmatter_fields() {
        let v = |s: &str| frontmatter_field(s, "version");

        assert_eq!(
            v("---\nname: foo\nversion: 1.4.2\n---\n# Hi").as_deref(),
            Some("1.4.2")
        );
        assert_eq!(
            v("---\nversion: \"2.0.0\"\n---\n").as_deref(),
            Some("2.0.0")
        );
        assert_eq!(v("---\r\nversion: 3.1\r\n---\r\n").as_deref(), Some("3.1"));
        assert_eq!(v("\u{feff}---\nversion: 4\n---\n").as_deref(), Some("4"));
        assert_eq!(v("---\nname: foo\n---\n"), None);
        assert_eq!(v("# heading\nversion: 9"), None);
        // Nested/indented keys are not top-level frontmatter fields.
        assert_eq!(v("---\nmeta:\n  version: 5\n---\n"), None);

        let n = |s: &str| frontmatter_field(s, "name");

        assert_eq!(
            n("---\nname: acme/demo\nversion: 1.0.0\n---\n").as_deref(),
            Some("acme/demo")
        );
        assert_eq!(n("---\nname: 'quoted'\n---\n").as_deref(), Some("quoted"));
        assert_eq!(n("---\nversion: 1\n---\n"), None);
    }

    #[test]
    fn build_manifest_infers_name_and_version_from_frontmatter() {
        let dir = std::env::temp_dir().join(format!("psmani-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);

        fs::create_dir_all(dir.join("scripts")).unwrap();
        fs::write(
            dir.join("SKILL.md"),
            "---\nname: acme/demo\nversion: 2.3.1\n---\n# Demo\n",
        )
        .unwrap();
        fs::write(dir.join("scripts/run.py"), "print(1)\n").unwrap();

        let opts = BuildOptions {
            name: None,
            version: None,
            kind: None,
        };
        let m = build_manifest(&dir, None, &opts).unwrap();

        assert_eq!(m.name, "acme/demo");
        assert_eq!(m.version.as_deref(), Some("2.3.1"));

        // An explicit --name/--version still wins over the frontmatter value.
        let opts = BuildOptions {
            name: Some("cli/name"),
            version: Some("9.9.9"),
            kind: None,
        };
        let m = build_manifest(&dir, None, &opts).unwrap();

        assert_eq!(m.name, "cli/name");
        assert_eq!(m.version.as_deref(), Some("9.9.9"));

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn md_ext_stripping() {
        assert_eq!(strip_md_ext("reviewer.md"), "reviewer");
        assert_eq!(strip_md_ext("REVIEWER.MD"), "REVIEWER");
        assert_eq!(strip_md_ext("notes.markdown"), "notes");
        assert_eq!(strip_md_ext("script.py"), "script.py");
    }
}
