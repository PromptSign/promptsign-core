// Trust bundles (spec/07 §5): an organization's roots in one signed, versioned
// document. A bundle is an ordinary file with an ordinary keyless sidecar
// signature (`promptsign sign trust-bundle.json`), so verifying one needs
// nothing beyond the verifier itself and publishing one needs no special tool.
//
// Installing trusts the bundle's own signers, which is why the CLI asks the
// user first. Every later version must be signed by a signer the installed
// version names, carry a higher version number, and not have expired.

use crate::bundle::PAYLOAD_TYPE;
use crate::keyless::verify_keyless_with;
use crate::managed::managed_trust_dir;
use crate::manifest::Manifest;
use crate::trustroot::{
    check_name, load_builtin, load_named_in, load_pinned, roots_dir, user_trust_dir, Root,
    DEFAULT_ROOT,
};
use crate::util::{format_iso8601, glob_match, parse_iso8601, sha256_hex};
use crate::Result;
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};

pub const TRUST_BUNDLE_SCHEMA: &str = "promptsign/trust-bundle/v1";
pub const BUNDLE_FILE: &str = "trust-bundle.json";
pub const SIDECAR_FILE: &str = "trust-bundle.json.psig.json";
const SOURCE_FILE: &str = "source.json";
/// How far in the future `issued` may be before a bundle is refused.
const MAX_CLOCK_SKEW: i64 = 300;

/// A signer a bundle accepts for its next version. `root` is resolved: the
/// built-in root's name, or `<bundle>/<root>`.
#[derive(Clone, Debug)]
pub struct BundleSigner {
    pub identity: String,
    pub issuer: String,
    pub root: String,
}

/// Where the publisher serves its revocation feed and who signs it
/// (spec/07 §5.1, spec/06 §3). `root` is resolved like a signer's.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BundleFeed {
    pub url: String,
    /// Glob over the feed signer's identity.
    pub identity: String,
    /// Glob over the feed signer's issuer; any issuer when absent.
    pub issuer: Option<String>,
    pub root: String,
}

#[derive(Clone)]
pub struct TrustBundle {
    /// The installed name. Every root is named `<name>/<root>`.
    pub name: String,
    /// The name the publisher suggests. Informative only.
    pub suggested_name: String,
    pub version: u64,
    pub issued: i64,
    pub expires: i64,
    pub roots: Vec<Root>,
    pub signers: Vec<BundleSigner>,
    pub revocation_feed: Option<BundleFeed>,
}

/// The signer whose signature a bundle carried.
#[derive(Clone, Debug)]
pub struct SeenSigner {
    pub identity: String,
    pub issuer: String,
    pub root: String,
}

/// What installing a candidate would do, for the user to confirm.
pub struct Check {
    pub bundle: TrustBundle,
    pub signer: SeenSigner,
    /// A bundle of this name is installed, and the candidate replaces it.
    pub update: bool,
    /// The candidate is byte for byte the installed version.
    pub unchanged: bool,
}

impl std::fmt::Debug for Check {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Check")
            .field("name", &self.bundle.name)
            .field("version", &self.bundle.version)
            .field("signer", &self.signer)
            .field("update", &self.update)
            .field("unchanged", &self.unchanged)
            .finish()
    }
}

pub struct Installed {
    pub bundle: TrustBundle,
    /// Where `trust fetch` refreshes it from. None for a file install.
    pub source: Option<String>,
    pub stale: bool,
    /// True for a bundle in the managed trust directory (spec/07 §2.4).
    pub managed: bool,
}

/// Parse and check a bundle document (spec/07 §5.1) to be installed as `name`.
pub fn parse_trust_bundle(name: &str, bytes: &[u8]) -> Result<TrustBundle> {
    check_name(name)?;

    let v: Value = serde_json::from_slice(bytes).map_err(|e| format!("trust bundle: {e}"))?;

    if v["schema"] != TRUST_BUNDLE_SCHEMA {
        return Err(format!(
            "not a trust bundle: schema is {}, expected {TRUST_BUNDLE_SCHEMA}",
            v["schema"]
        ));
    }

    let version = v["version"]
        .as_u64()
        .filter(|n| *n >= 1)
        .ok_or("trust bundle version must be an integer of at least 1")?;
    let time = |key: &str| {
        v[key]
            .as_str()
            .and_then(parse_iso8601)
            .ok_or_else(|| format!("trust bundle {key} is not an RFC 3339 time"))
    };
    let issued = time("issued")?;
    let expires = time("expires")?;

    if expires <= issued {
        return Err("trust bundle expires before it is issued".to_string());
    }

    let docs = v["roots"]
        .as_object()
        .filter(|o| !o.is_empty())
        .ok_or("trust bundle lists no roots")?;
    let mut roots: Vec<Root> = Vec::new();

    for (key, doc) in docs {
        check_name(key).map_err(|e| format!("trust bundle root: {e}"))?;

        let mut root = Root::from_trusted_root(&format!("{name}/{key}"), doc)
            .map_err(|e| format!("trust bundle root \"{key}\": {e}"))?;

        if let Some(twin) = roots.iter().find(|r| r.fingerprint == root.fingerprint) {
            return Err(format!(
                "trust bundle lists the same root twice: \"{key}\" and \"{}\"",
                twin.name
            ));
        }
        root.expires = Some(expires);
        roots.push(root);
    }

    // A signer's or a feed's `root`: the built-in root or one of this bundle's.
    let resolve_root = |root: String, whose: &str| {
        if root == DEFAULT_ROOT {
            Ok(root)
        } else if docs.contains_key(&root) {
            Ok(format!("{name}/{root}"))
        } else {
            Err(format!(
                "trust bundle {whose} root \"{root}\" is neither {DEFAULT_ROOT} nor one of the bundle's roots"
            ))
        }
    };
    let mut signers = Vec::new();

    for s in v["signers"]
        .as_array()
        .filter(|a| !a.is_empty())
        .ok_or("trust bundle lists no signers")?
    {
        let field = |key: &str| {
            s[key]
                .as_str()
                .filter(|x| !x.is_empty())
                .map(str::to_string)
                .ok_or_else(|| format!("trust bundle signer has no {key}"))
        };
        signers.push(BundleSigner {
            root: resolve_root(field("root")?, "signer")?,
            identity: field("identity")?,
            issuer: field("issuer")?,
        });
    }

    let revocation_feed = match v.get("revocationFeed") {
        None => None,
        Some(f) => {
            let field = |key: &str| {
                f[key]
                    .as_str()
                    .filter(|x| !x.is_empty())
                    .map(str::to_string)
                    .ok_or_else(|| format!("trust bundle revocationFeed has no {key}"))
            };

            if f.get("issuer").is_some_and(|i| !i.is_string()) {
                return Err("trust bundle revocationFeed issuer is not a string".to_string());
            }
            Some(BundleFeed {
                url: field("url")?,
                identity: field("identity")?,
                issuer: f["issuer"].as_str().map(str::to_string),
                root: resolve_root(field("root")?, "revocationFeed")?,
            })
        }
    };

    Ok(TrustBundle {
        name: name.to_string(),
        suggested_name: v["name"].as_str().unwrap_or_default().to_string(),
        version,
        issued,
        expires,
        roots,
        signers,
        revocation_feed,
    })
}

/// Steps 1 and 2 of spec/07 §5.2: the sidecar is a valid keyless signature
/// over exactly these bytes, by one of `accept`'s signers, chained to that
/// signer's root (the built-in root or one of `accept`'s).
fn verify_signed(
    bytes: &[u8],
    sidecar: &Value,
    accept: &TrustBundle,
    public: &[Root],
) -> Result<SeenSigner> {
    if sidecar["envelope"]["payloadType"] != PAYLOAD_TYPE {
        return Err("trust bundle signature is not a PromptSign signature".to_string());
    }

    let roots: Vec<Root> = public.iter().chain(&accept.roots).cloned().collect();
    let kv =
        verify_keyless_with(sidecar, &roots).map_err(|e| format!("trust bundle signature: {e}"))?;
    let manifest: Manifest = serde_json::from_slice(&kv.payload)
        .map_err(|e| format!("trust bundle signature: manifest: {e}"))?;
    let covers = manifest.scope.as_deref() == Some("file")
        && manifest.files.len() == 1
        && manifest.files[0].sha256 == sha256_hex(bytes);

    if !covers {
        return Err(format!(
            "trust bundle signature: modified: {BUNDLE_FILE} (the signature covers other bytes)"
        ));
    }

    let seen = SeenSigner {
        identity: kv.identity,
        issuer: kv.issuer,
        root: kv.root,
    };
    let listed = accept.signers.iter().any(|s| {
        glob_match(&s.identity, &seen.identity) && s.issuer == seen.issuer && s.root == seen.root
    });

    if !listed {
        return Err(format!(
            "\"{}\" (issuer {}, root {}) is not a signer of trust bundle \"{}\" version {}",
            seen.identity, seen.issuer, seen.root, accept.name, accept.version
        ));
    }
    Ok(seen)
}

fn bundles_dir(dir: &Path) -> PathBuf {
    dir.join("bundles")
}

fn read(path: &Path) -> Result<Vec<u8>> {
    fs::read(path).map_err(|e| format!("{}: {e}", path.display()))
}

/// The installed bundle `name` and its bytes, re-verified against its own
/// signers (spec/07 §5.5). None when no such bundle is installed.
fn load_installed(dir: &Path, name: &str, public: &[Root]) -> Result<Option<(Installed, Vec<u8>)>> {
    let bdir = bundles_dir(dir).join(name);

    if !bdir.is_dir() {
        return Ok(None);
    }

    let stored = |e: String| format!("stored trust bundle \"{name}\": {e}");
    let bytes = read(&bdir.join(BUNDLE_FILE)).map_err(stored)?;
    let sidecar: Value = serde_json::from_slice(&read(&bdir.join(SIDECAR_FILE)).map_err(stored)?)
        .map_err(|e| stored(e.to_string()))?;
    let bundle = parse_trust_bundle(name, &bytes).map_err(stored)?;

    verify_signed(&bytes, &sidecar, &bundle, public).map_err(stored)?;

    let source = fs::read(bdir.join(SOURCE_FILE))
        .ok()
        .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
        .and_then(|v| v["url"].as_str().map(str::to_string));

    Ok(Some((
        Installed {
            bundle,
            source,
            stale: false,
            managed: false,
        },
        bytes,
    )))
}

pub(crate) fn installed_in(dir: &Path, public: &[Root], now: i64) -> Result<Vec<Installed>> {
    let bdir = bundles_dir(dir);
    let mut names: Vec<String> = match fs::read_dir(&bdir) {
        Ok(entries) => entries
            .flatten()
            .filter(|e| e.path().is_dir())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| !n.starts_with('.'))
            .collect(),
        Err(_) => return Ok(Vec::new()),
    };
    let mut out = Vec::new();

    names.sort();
    for name in names {
        if let Some((mut installed, _)) = load_installed(dir, &name, public)? {
            installed.stale = installed.bundle.expires <= now;
            out.push(installed);
        }
    }
    Ok(out)
}

fn check_in(
    dir: &Path,
    public: &[Root],
    named: &[Root],
    name: &str,
    bytes: &[u8],
    sidecar: &Value,
    now: i64,
) -> Result<Check> {
    let candidate = parse_trust_bundle(name, bytes)?;
    let current = load_installed(dir, name, public)?;

    if let Some((cur, cur_bytes)) = &current {
        if cur_bytes == bytes {
            let signer = verify_signed(bytes, sidecar, &cur.bundle, public)?;

            return Ok(Check {
                bundle: candidate,
                signer,
                update: true,
                unchanged: true,
            });
        }
    }

    let accept = current
        .as_ref()
        .map(|(c, _)| &c.bundle)
        .unwrap_or(&candidate);
    let signer = verify_signed(bytes, sidecar, accept, public)?;

    if let Some((cur, _)) = &current {
        if candidate.version <= cur.bundle.version {
            return Err(format!(
                "trust bundle \"{name}\" version {} is not newer than the installed version {}: refusing a rollback",
                candidate.version, cur.bundle.version
            ));
        }
    }
    if candidate.expires <= now {
        return Err(format!(
            "trust bundle \"{name}\" expired at {}",
            format_iso8601(candidate.expires)
        ));
    }
    if candidate.issued > now + MAX_CLOCK_SKEW {
        return Err(format!(
            "trust bundle \"{name}\" is issued in the future ({})",
            format_iso8601(candidate.issued)
        ));
    }

    // A root may be trusted under one name only, so policy names stay
    // unambiguous. This bundle's own installed roots do not count.
    let mut others: Vec<Root> = public.iter().chain(named).cloned().collect();

    for other in installed_in(dir, public, now)? {
        if other.bundle.name != name {
            others.extend(other.bundle.roots);
        }
    }
    for r in &candidate.roots {
        if let Some(o) = others.iter().find(|o| o.fingerprint == r.fingerprint) {
            return Err(format!(
                "root \"{}\" of trust bundle \"{name}\" is already trusted as \"{}\"",
                r.name, o.name
            ));
        }
    }

    Ok(Check {
        bundle: candidate,
        signer,
        update: current.is_some(),
        unchanged: false,
    })
}

/// Everything §5.2 checks before installing `bytes` as bundle `name` in the
/// trust directory `dir`, whose pinned pair is the built-in root. Writes
/// nothing.
pub fn check_trust_bundle(
    dir: &Path,
    name: &str,
    bytes: &[u8],
    sidecar: &Value,
    now: i64,
) -> Result<Check> {
    let public: Vec<Root> = load_pinned(dir)?.into_iter().collect();
    let named = load_named_in(&roots_dir(dir))?;

    check_in(dir, &public, &named, name, bytes, sidecar, now)
}

/// The user's trust directory, or the managed one.
pub fn layer_trust_dir(managed: bool) -> PathBuf {
    if managed {
        managed_trust_dir()
    } else {
        user_trust_dir()
    }
}

/// `check_trust_bundle` against the user's (`managed` false) or the managed
/// trust directory and the built-in root. A user bundle may not take the
/// name or a root of a managed root or bundle (spec/07 §2.4).
pub fn check_layer_trust_bundle(
    managed: bool,
    name: &str,
    bytes: &[u8],
    sidecar: &Value,
    now: i64,
) -> Result<Check> {
    let public: Vec<Root> = load_builtin()?.into_iter().collect();
    let dir = layer_trust_dir(managed);
    let mut named = load_named_in(&roots_dir(&dir))?;

    if !managed {
        let mdir = managed_trust_dir();
        let mut taken = load_named_in(&roots_dir(&mdir))?;

        for b in installed_in(&mdir, &public, now)? {
            if b.bundle.name == name {
                return Err(format!(
                    "trust bundle \"{name}\" is managed on this machine"
                ));
            }
            taken.extend(b.bundle.roots);
        }
        if taken.iter().any(|r| r.name == name) {
            return Err(format!("\"{name}\" is the name of a managed trust root"));
        }
        named.extend(taken);
    }
    check_in(&dir, &public, &named, name, bytes, sidecar, now)
}

/// `check_layer_trust_bundle` for the user's trust directory.
pub fn check_user_trust_bundle(
    name: &str,
    bytes: &[u8],
    sidecar: &Value,
    now: i64,
) -> Result<Check> {
    check_layer_trust_bundle(false, name, bytes, sidecar, now)
}

/// Every installed bundle in `dir`, re-verified, with its staleness at `now`.
pub fn installed_bundles(dir: &Path, now: i64) -> Result<Vec<Installed>> {
    let public: Vec<Root> = load_pinned(dir)?.into_iter().collect();

    installed_in(dir, &public, now)
}

/// `installed_bundles` for the user's (`managed` false) or the managed trust
/// directory, with the built-in root as the public root.
pub fn installed_layer_bundles(managed: bool, now: i64) -> Result<Vec<Installed>> {
    let public: Vec<Root> = load_builtin()?.into_iter().collect();
    let mut out = installed_in(&layer_trust_dir(managed), &public, now)?;

    for b in &mut out {
        b.managed = managed;
    }
    Ok(out)
}

/// `installed_bundles` for the user's trust directory.
pub fn installed_user_bundles(now: i64) -> Result<Vec<Installed>> {
    installed_layer_bundles(false, now)
}

/// Write a bundle that `check_trust_bundle` accepted. Replaces an installed
/// version in one step. A `None` source keeps the installed one.
pub fn store_trust_bundle(
    dir: &Path,
    name: &str,
    bytes: &[u8],
    sidecar: &[u8],
    source: Option<&str>,
) -> Result<()> {
    check_name(name)?;

    let parent = bundles_dir(dir);
    let target = parent.join(name);
    let pid = std::process::id();
    let staging = parent.join(format!(".{name}.new-{pid}"));
    let retired = parent.join(format!(".{name}.old-{pid}"));
    let io = |p: &Path, e: std::io::Error| format!("{}: {e}", p.display());
    let source = source.map(str::to_string).or_else(|| {
        fs::read(target.join(SOURCE_FILE))
            .ok()
            .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
            .and_then(|v| v["url"].as_str().map(str::to_string))
    });

    let _ = fs::remove_dir_all(&staging);
    fs::create_dir_all(&staging).map_err(|e| io(&staging, e))?;
    fs::write(staging.join(BUNDLE_FILE), bytes).map_err(|e| io(&staging, e))?;
    fs::write(staging.join(SIDECAR_FILE), sidecar).map_err(|e| io(&staging, e))?;
    if let Some(url) = source {
        fs::write(
            staging.join(SOURCE_FILE),
            serde_json::to_string_pretty(&json!({ "url": url })).unwrap() + "\n",
        )
        .map_err(|e| io(&staging, e))?;
    }
    if target.exists() {
        let _ = fs::remove_dir_all(&retired);
        fs::rename(&target, &retired).map_err(|e| io(&target, e))?;
    }
    fs::rename(&staging, &target).map_err(|e| io(&target, e))?;
    let _ = fs::remove_dir_all(&retired);
    Ok(())
}

/// Remove the installed bundle `name` and with it all its roots.
pub fn remove_trust_bundle(dir: &Path, name: &str) -> Result<()> {
    check_name(name)?;

    let target = bundles_dir(dir).join(name);

    if !target.is_dir() {
        return Err(format!("no trust bundle named \"{name}\""));
    }
    fs::remove_dir_all(&target).map_err(|e| format!("{}: {e}", target.display()))
}
