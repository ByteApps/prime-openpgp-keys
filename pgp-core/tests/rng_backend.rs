//! Structural entropy contract — the ONLY defence against the disclosed firmware bug
//! #1 (a fixed-seed CSPRNG is statistically perfect; `entropy.rs`'s
//! battery can never catch it, by construction — see
//! `common/entropy_battery.rs`'s module doc).
//!
//! Five checks, each written as a pure function over a plain text/graph
//! input plus a thin wrapper that feeds it the real repo files, so a
//! broken input is a permanent regression test rather than a one-off
//! edit:
//!
//!   1. the workspace `Cargo.toml` has a `[patch.crates-io]` that
//!      redirects `getrandom` to `vendor/getrandom`;
//!   2. `vendor/getrandom/src/lib.rs`'s backend `cfg_if!` chain has a
//!      `#[cfg(keyos)]` arm BEFORE the `feature = "custom"` arm, and its
//!      final fallback arm is `compile_error!` (ordering is load-bearing:
//!      if `custom` ever won, an unflagged device build would silently
//!      rebind instead of failing to build);
//!   3. `vendor/getrandom/src/xous.rs` still calls the fill-verification
//!      hardening (`write_sentinel`/`looks_unfilled`/`words_for`);
//!   4. `register_custom_getrandom!` appears nowhere in the repo outside
//!      `vendor/getrandom` itself;
//!   5. the dependency graph — the important one. `cargo metadata
//!      --filter-platform <target>` (which does real `cfg()` evaluation,
//!      unlike a naive dep_kinds walk — see the module doc on
//!      `forbidden_reachable` for why that matters) is walked from the
//!      `pgp-core` root over normal/build edges only, and the ONLY
//!      `getrandom` reachable must be the vendored 0.2.x path
//!      dependency, and the only `rand_core` reachable must be 0.6.x.
//!      `rpgp 0.20` happens to use `rand 0.8`, which lands on the
//!      patched `getrandom 0.2`; a bump to a crate on `rand 0.9` would
//!      reach `getrandom 0.3`, which `[patch.crates-io]` does NOT cover,
//!      and would silently bypass the TRNG.

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::process::Command;

// ===========================================================================
// 1. [patch.crates-io] redirects getrandom to vendor/getrandom
// ===========================================================================

fn check_patch_redirects_getrandom(cargo_toml: &str) -> Result<(), String> {
    let idx = cargo_toml
        .find("[patch.crates-io]")
        .ok_or_else(|| "no `[patch.crates-io]` section in Cargo.toml".to_string())?;
    let rest = &cargo_toml[idx..];
    // The section ends at the next top-level table header, or EOF.
    let section_end = rest[1..].find("\n[").map(|p| p + 1).unwrap_or(rest.len());
    let section = &rest[..section_end];

    let gr_idx = section
        .find("getrandom")
        .ok_or_else(|| "`[patch.crates-io]` has no `getrandom` entry".to_string())?;
    let after = &section[gr_idx..];
    let line_end = after.find('\n').unwrap_or(after.len());
    let line = &after[..line_end];
    if !line.contains("vendor/getrandom") {
        return Err(format!(
            "`[patch.crates-io]` getrandom entry does not point at vendor/getrandom: `{line}`"
        ));
    }
    Ok(())
}

#[test]
fn real_workspace_manifest_patches_getrandom_to_vendor() {
    let text = include_str!("../../Cargo.toml");
    check_patch_redirects_getrandom(text).unwrap_or_else(|e| panic!("{e}"));
}

#[test]
fn patch_check_mutation_missing_section_fails() {
    let toml = "[dependencies]\ngetrandom = \"0.2\"\n";
    let e = check_patch_redirects_getrandom(toml).unwrap_err();
    assert!(e.contains("no `[patch.crates-io]`"), "{e}");
}

#[test]
fn patch_check_mutation_section_without_getrandom_fails() {
    let toml = "[patch.crates-io]\nfoo = { path = \"vendor/foo\" }\n\n[dependencies]\ngetrandom = \"0.2\"\n";
    let e = check_patch_redirects_getrandom(toml).unwrap_err();
    assert!(e.contains("no `getrandom` entry"), "{e}");
}

#[test]
fn patch_check_mutation_wrong_target_path_fails() {
    let toml = "[patch.crates-io]\ngetrandom = { path = \"vendor/not-getrandom\" }\n";
    let e = check_patch_redirects_getrandom(toml).unwrap_err();
    assert!(e.contains("does not point at vendor/getrandom"), "{e}");
}

#[test]
fn patch_check_mutation_correct_patch_passes() {
    let toml = "[package]\nname = \"x\"\n\n[patch.crates-io]\ngetrandom = { path = \"vendor/getrandom\" }\n\n[dependencies]\nfoo = \"1\"\n";
    assert!(check_patch_redirects_getrandom(toml).is_ok());
}

// ===========================================================================
// 2. backend cfg_if ordering: keyos before custom, fallback is compile_error!
// ===========================================================================

fn check_backend_ordering(lib_rs: &str) -> Result<(), String> {
    let chain_start = lib_rs
        .find("cfg_if! {")
        .ok_or_else(|| "no `cfg_if! { ... }` backend-selection block found".to_string())?;
    let chain = &lib_rs[chain_start..];

    let keyos_marker = "#[cfg(keyos)]";
    let custom_marker = "#[cfg(feature = \"custom\")]";
    let keyos_pos = chain
        .find(keyos_marker)
        .ok_or_else(|| format!("no `{keyos_marker}` arm found in the backend cfg_if chain"))?;
    let custom_pos = chain
        .find(custom_marker)
        .ok_or_else(|| format!("no `{custom_marker}` arm found in the backend cfg_if chain"))?;
    if keyos_pos >= custom_pos {
        return Err(format!(
            "the `{keyos_marker}` arm must appear BEFORE the `{custom_marker}` arm in the backend \
             cfg_if chain (chain-relative bytes {keyos_pos} vs {custom_pos}) — otherwise an \
             unflagged device build could silently rebind to a custom getrandom instead of \
             failing to build"
        ));
    }

    let last_else = chain
        .rfind("} else {")
        .ok_or_else(|| "no final catch-all `} else { ... }` arm found in the backend cfg_if chain".to_string())?;
    if last_else < custom_pos {
        return Err(
            "the final catch-all arm appears before the `custom` feature arm in the backend cfg_if chain"
                .to_string(),
        );
    }
    // The fallback arm's own body: from `} else {` up to a bounded window,
    // wide enough for the real arm and not so wide it could pick up
    // unrelated code appearing later in the file.
    let tail = &chain[last_else..chain.len().min(last_else + 500).max(last_else)];
    if !tail.contains("compile_error!") {
        return Err(format!(
            "the final catch-all arm does not call compile_error! — an unsupported target would \
             silently compile instead of failing the build:\n{tail}"
        ));
    }
    Ok(())
}

#[test]
fn real_backend_chain_orders_keyos_before_custom_with_compile_error_fallback() {
    let text = include_str!("../../vendor/getrandom/src/lib.rs");
    check_backend_ordering(text).unwrap_or_else(|e| panic!("{e}"));
}

const GOOD_CHAIN: &str = r#"
cfg_if! {
    if #[cfg(windows)] {
        mod windows_imp;
    } else if #[cfg(keyos)] {
        mod xous_imp;
    } else if #[cfg(feature = "custom")] {
        use custom as imp;
    } else {
        compile_error!("target is not supported");
    }
}
"#;

#[test]
fn backend_order_mutation_good_chain_passes() {
    assert!(check_backend_ordering(GOOD_CHAIN).is_ok());
}

#[test]
fn backend_order_mutation_custom_before_keyos_fails() {
    let bad = r#"
cfg_if! {
    if #[cfg(feature = "custom")] {
        use custom as imp;
    } else if #[cfg(keyos)] {
        mod xous_imp;
    } else {
        compile_error!("target is not supported");
    }
}
"#;
    let e = check_backend_ordering(bad).unwrap_err();
    assert!(e.contains("must appear BEFORE"), "{e}");
}

#[test]
fn backend_order_mutation_missing_keyos_arm_fails() {
    let bad = r#"
cfg_if! {
    if #[cfg(feature = "custom")] {
        use custom as imp;
    } else {
        compile_error!("target is not supported");
    }
}
"#;
    let e = check_backend_ordering(bad).unwrap_err();
    assert!(e.contains("cfg(keyos)"), "{e}");
}

#[test]
fn backend_order_mutation_missing_custom_arm_fails() {
    let bad = r#"
cfg_if! {
    if #[cfg(keyos)] {
        mod xous_imp;
    } else {
        compile_error!("target is not supported");
    }
}
"#;
    let e = check_backend_ordering(bad).unwrap_err();
    assert!(e.contains("feature = \"custom\""), "{e}");
}

#[test]
fn backend_order_mutation_fallback_not_compile_error_fails() {
    let bad = r#"
cfg_if! {
    if #[cfg(keyos)] {
        mod xous_imp;
    } else if #[cfg(feature = "custom")] {
        use custom as imp;
    } else {
        use custom as imp;
    }
}
"#;
    let e = check_backend_ordering(bad).unwrap_err();
    assert!(e.contains("compile_error"), "{e}");
}

// ===========================================================================
// 3. xous.rs still calls the fill-verification hardening
// ===========================================================================

fn check_xous_hardening_calls(xous_rs: &str) -> Result<(), String> {
    for call in ["write_sentinel(", "looks_unfilled(", "words_for("] {
        if !xous_rs.contains(call) {
            return Err(format!(
                "xous.rs no longer calls `{call}...)` — the fill-verification hardening may have \
                 been reverted"
            ));
        }
    }
    Ok(())
}

#[test]
fn real_xous_backend_still_calls_the_hardening_fns() {
    let text = include_str!("../../vendor/getrandom/src/xous.rs");
    check_xous_hardening_calls(text).unwrap_or_else(|e| panic!("{e}"));
}

#[test]
fn xous_calls_mutation_removed_write_sentinel_fails() {
    let text = include_str!("../../vendor/getrandom/src/xous.rs");
    let mutated = text.replace("write_sentinel(", "REMOVED_CALL(");
    let e = check_xous_hardening_calls(&mutated).unwrap_err();
    assert!(e.contains("write_sentinel"), "{e}");
}

#[test]
fn xous_calls_mutation_removed_looks_unfilled_fails() {
    let text = include_str!("../../vendor/getrandom/src/xous.rs");
    let mutated = text.replace("looks_unfilled(", "REMOVED_CALL(");
    let e = check_xous_hardening_calls(&mutated).unwrap_err();
    assert!(e.contains("looks_unfilled"), "{e}");
}

#[test]
fn xous_calls_mutation_removed_words_for_fails() {
    let text = include_str!("../../vendor/getrandom/src/xous.rs");
    let mutated = text.replace("words_for(", "REMOVED_CALL(");
    let e = check_xous_hardening_calls(&mutated).unwrap_err();
    assert!(e.contains("words_for"), "{e}");
}

// ===========================================================================
// 4. register_custom_getrandom! appears nowhere outside vendor/getrandom
// ===========================================================================

fn check_no_custom_registration_outside_vendor<'a>(
    files: impl IntoIterator<Item = &'a (String, String)>,
) -> Result<(), String> {
    let offenders: Vec<&str> = files
        .into_iter()
        .filter(|(_, content)| content.contains("register_custom_getrandom!"))
        .map(|(path, _)| path.as_str())
        .collect();
    if offenders.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "register_custom_getrandom! found outside vendor/getrandom in: {}",
            offenders.join(", ")
        ))
    }
}

#[test]
fn custom_registration_mutation_offender_detected() {
    let files = vec![
        ("src/main.rs".to_string(), "fn main() {}".to_string()),
        ("src/evil.rs".to_string(), "register_custom_getrandom!(always_fail);".to_string()),
    ];
    let e = check_no_custom_registration_outside_vendor(&files).unwrap_err();
    assert!(e.contains("src/evil.rs"), "{e}");
}

#[test]
fn custom_registration_mutation_clean_set_passes() {
    let files = vec![("src/main.rs".to_string(), "fn main() {}".to_string())];
    assert!(check_no_custom_registration_outside_vendor(&files).is_ok());
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("pgp-core has a parent directory (the workspace root)")
        .to_path_buf()
}

/// Walk the repo tree collecting `.rs` file contents. Never follows
/// symlinks (the SDK-synced `ui/ui`, `resources/*`, and the private-docs
/// symlinks all point outside the repo) and skips `target`/`.git`.
fn collect_repo_rs_files(root: &Path) -> Vec<(PathBuf, String)> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let Ok(ft) = entry.file_type() else { continue };
            if ft.is_symlink() {
                continue;
            }
            let path = entry.path();
            if ft.is_dir() {
                let name = entry.file_name();
                if name == "target" || name == ".git" {
                    continue;
                }
                stack.push(path);
            } else if ft.is_file() && path.extension().is_some_and(|e| e == "rs") {
                if let Ok(content) = std::fs::read_to_string(&path) {
                    out.push((path, content));
                }
            }
        }
    }
    out
}

#[test]
fn real_repo_never_registers_custom_getrandom_outside_vendor() {
    let root = workspace_root();
    let vendor_getrandom = root.join("vendor").join("getrandom");
    // Excludes THIS file: it deliberately spells the macro name in its
    // own doc comment and mutation-test fixtures above, which is not a
    // real registration site.
    let self_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests").join("rng_backend.rs");
    let files: Vec<(String, String)> = collect_repo_rs_files(&root)
        .into_iter()
        .filter(|(p, _)| !p.starts_with(&vendor_getrandom) && p != &self_path)
        .map(|(p, c)| (p.display().to_string(), c))
        .collect();
    assert!(!files.is_empty(), "sanity check: the repo .rs file scan found nothing — the walker is broken");
    check_no_custom_registration_outside_vendor(&files).unwrap_or_else(|e| panic!("{e}"));
}

// ===========================================================================
// 5. Dependency-graph guard — the important one.
// ===========================================================================
//
// A naive walk of `resolve.nodes` that only filters on `dep_kinds` (and
// ignores each edge's `target` cfg-gate) gives a FALSE POSITIVE failure
// here: `rand 0.9`/`rand_core 0.9`/`getrandom 0.3`/`getrandom 0.4` are
// all in `Cargo.lock` (pulled in by `jobserver`/`tempfile`/`rav1e`'s dev
// or platform-specific requirements) and are reachable by a target-blind
// walk — verified empirically against this repo's real `Cargo.lock`,
// where they show up gated behind `cfg(windows)` and `cfg(fuzzing)`,
// neither of which is ever true for our real builds. `cargo metadata
// --filter-platform <target>` does the real `cfg()` evaluation (via
// rustc) instead of us re-implementing one, which is why the wrapper
// below shells out to it for both the host triple and the device
// target rather than parsing a target-blind `cargo metadata` dump.

fn dep_kind_is_normal_or_build(dep_kinds: &serde_json::Value) -> bool {
    match dep_kinds.as_array() {
        None => false,
        Some(arr) => arr.iter().any(|dk| match dk.get("kind") {
            None => true,
            Some(serde_json::Value::Null) => true,
            Some(serde_json::Value::String(s)) => s == "build",
            _ => false,
        }),
    }
}

/// Pure function over a `cargo metadata --format-version 1` JSON
/// document (already platform-filtered by the caller): BFS from
/// `resolve.root` over normal/build edges only, and report every
/// reachable `getrandom` that isn't the vendored 0.2.x path dependency,
/// and every reachable `rand_core` that isn't 0.6.x. An empty result
/// means the graph is clean.
fn forbidden_reachable(metadata_json: &str) -> Result<Vec<String>, String> {
    let v: serde_json::Value =
        serde_json::from_str(metadata_json).map_err(|e| format!("invalid `cargo metadata` JSON: {e}"))?;

    let packages = v
        .get("packages")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| "metadata JSON has no `packages` array".to_string())?;
    let mut pkg_by_id: HashMap<&str, (&str, &str)> = HashMap::new();
    for p in packages {
        let id = p.get("id").and_then(serde_json::Value::as_str);
        let name = p.get("name").and_then(serde_json::Value::as_str);
        let version = p.get("version").and_then(serde_json::Value::as_str);
        if let (Some(id), Some(name), Some(version)) = (id, name, version) {
            pkg_by_id.insert(id, (name, version));
        }
    }

    let resolve = v
        .get("resolve")
        .ok_or_else(|| "metadata JSON has no `resolve` section".to_string())?;
    let root = resolve
        .get("root")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "`resolve.root` is missing or null (virtual workspace root?)".to_string())?;
    let nodes = resolve
        .get("nodes")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| "`resolve.nodes` is missing".to_string())?;
    let mut node_by_id: HashMap<&str, &serde_json::Value> = HashMap::new();
    for n in nodes {
        if let Some(id) = n.get("id").and_then(serde_json::Value::as_str) {
            node_by_id.insert(id, n);
        }
    }

    let mut seen: HashSet<&str> = HashSet::new();
    seen.insert(root);
    let mut queue: VecDeque<&str> = VecDeque::new();
    queue.push_back(root);
    while let Some(cur) = queue.pop_front() {
        let Some(node) = node_by_id.get(cur) else { continue };
        let Some(deps) = node.get("deps").and_then(serde_json::Value::as_array) else { continue };
        for dep in deps {
            let empty = serde_json::Value::Array(vec![]);
            let dep_kinds = dep.get("dep_kinds").unwrap_or(&empty);
            if !dep_kind_is_normal_or_build(dep_kinds) {
                continue;
            }
            let Some(dep_id) = dep.get("pkg").and_then(serde_json::Value::as_str) else { continue };
            if seen.insert(dep_id) {
                queue.push_back(dep_id);
            }
        }
    }

    let mut ids: Vec<&str> = seen.into_iter().collect();
    ids.sort_unstable();

    let mut problems = Vec::new();
    for id in ids {
        let Some(&(name, version)) = pkg_by_id.get(id) else { continue };
        if name == "getrandom" {
            let is_vendored_patch = version.starts_with("0.2.") && id.starts_with("path+file://") && id.contains("vendor/getrandom");
            if !is_vendored_patch {
                problems.push(format!(
                    "getrandom {version} ({id}) is reachable via a normal/build dependency from the \
                     root package, but only the vendored path dependency (vendor/getrandom, redirected \
                     by [patch.crates-io]) is allowed. This means [patch.crates-io] stopped applying to \
                     this dependency, so device key generation would silently stop using the KeyOS TRNG."
                ));
            }
        } else if name == "rand_core" && !version.starts_with("0.6.") {
            problems.push(format!(
                "rand_core {version} ({id}) is reachable via a normal/build dependency from the root \
                 package; only 0.6.x is allowed. rand_core 0.9 reaches getrandom 0.3, which \
                 [patch.crates-io] getrandom -> vendor/getrandom does NOT cover (the patch only \
                 redirects the 0.2.x family) — a dependency bump that pulls this in would silently \
                 route device key generation around the TRNG patch."
            ));
        }
    }
    Ok(problems)
}

// --- mutation tests over hand-authored minimal metadata documents ---

const GOOD_GRAPH: &str = r#"{
  "packages": [
    {"id": "path+file:///repo/pgp-core#0.1.0", "name": "pgp-core", "version": "0.1.0"},
    {"id": "registry+https://x#rand@0.8.6", "name": "rand", "version": "0.8.6"},
    {"id": "registry+https://x#rand_core@0.6.4", "name": "rand_core", "version": "0.6.4"},
    {"id": "path+file:///repo/vendor/getrandom#0.2.10", "name": "getrandom", "version": "0.2.10"}
  ],
  "resolve": {
    "root": "path+file:///repo/pgp-core#0.1.0",
    "nodes": [
      {"id": "path+file:///repo/pgp-core#0.1.0", "deps": [
        {"pkg": "registry+https://x#rand@0.8.6", "dep_kinds": [{"kind": null}]}
      ]},
      {"id": "registry+https://x#rand@0.8.6", "deps": [
        {"pkg": "registry+https://x#rand_core@0.6.4", "dep_kinds": [{"kind": null}]}
      ]},
      {"id": "registry+https://x#rand_core@0.6.4", "deps": [
        {"pkg": "path+file:///repo/vendor/getrandom#0.2.10", "dep_kinds": [{"kind": null}]}
      ]},
      {"id": "path+file:///repo/vendor/getrandom#0.2.10", "deps": []}
    ]
  }
}"#;

#[test]
fn graph_mutation_good_shape_is_clean() {
    let problems = forbidden_reachable(GOOD_GRAPH).expect("graph check should run");
    assert!(problems.is_empty(), "{problems:?}");
}

#[test]
fn graph_mutation_rand_core_09_via_normal_dep_is_caught() {
    let bad = r#"{
      "packages": [
        {"id": "path+file:///repo/pgp-core#0.1.0", "name": "pgp-core", "version": "0.1.0"},
        {"id": "registry+https://x#rand_core@0.9.5", "name": "rand_core", "version": "0.9.5"}
      ],
      "resolve": {
        "root": "path+file:///repo/pgp-core#0.1.0",
        "nodes": [
          {"id": "path+file:///repo/pgp-core#0.1.0", "deps": [
            {"pkg": "registry+https://x#rand_core@0.9.5", "dep_kinds": [{"kind": null}]}
          ]},
          {"id": "registry+https://x#rand_core@0.9.5", "deps": []}
        ]
      }
    }"#;
    let problems = forbidden_reachable(bad).expect("graph check should run");
    assert_eq!(problems.len(), 1, "{problems:?}");
    assert!(problems[0].contains("rand_core"), "{problems:?}");
    assert!(problems[0].contains("0.9.5"), "{problems:?}");
}

#[test]
fn graph_mutation_unvendored_getrandom_02_is_caught() {
    // Same version as the real patch (0.2.x) but a plain registry
    // source, not the vendored path — proves the check isn't just a
    // version-string check, it verifies the patch actually took effect.
    let bad = r#"{
      "packages": [
        {"id": "path+file:///repo/pgp-core#0.1.0", "name": "pgp-core", "version": "0.1.0"},
        {"id": "registry+https://x#getrandom@0.2.10", "name": "getrandom", "version": "0.2.10"}
      ],
      "resolve": {
        "root": "path+file:///repo/pgp-core#0.1.0",
        "nodes": [
          {"id": "path+file:///repo/pgp-core#0.1.0", "deps": [
            {"pkg": "registry+https://x#getrandom@0.2.10", "dep_kinds": [{"kind": null}]}
          ]},
          {"id": "registry+https://x#getrandom@0.2.10", "deps": []}
        ]
      }
    }"#;
    let problems = forbidden_reachable(bad).expect("graph check should run");
    assert_eq!(problems.len(), 1, "{problems:?}");
    assert!(problems[0].contains("getrandom"), "{problems:?}");
    assert!(problems[0].contains("stopped applying"), "{problems:?}");
}

#[test]
fn graph_mutation_dev_only_edge_to_forbidden_version_is_ignored() {
    // Proves the kind filter actually excludes dev-dependencies: if it
    // didn't, this fixture would report a problem.
    let dev_only = r#"{
      "packages": [
        {"id": "path+file:///repo/pgp-core#0.1.0", "name": "pgp-core", "version": "0.1.0"},
        {"id": "registry+https://x#rand_core@0.9.5", "name": "rand_core", "version": "0.9.5"}
      ],
      "resolve": {
        "root": "path+file:///repo/pgp-core#0.1.0",
        "nodes": [
          {"id": "path+file:///repo/pgp-core#0.1.0", "deps": [
            {"pkg": "registry+https://x#rand_core@0.9.5", "dep_kinds": [{"kind": "dev"}]}
          ]},
          {"id": "registry+https://x#rand_core@0.9.5", "deps": []}
        ]
      }
    }"#;
    let problems = forbidden_reachable(dev_only).expect("graph check should run");
    assert!(problems.is_empty(), "dev-only edge must not be followed: {problems:?}");
}

#[test]
fn graph_mutation_build_kind_edge_to_forbidden_version_is_caught() {
    // The mirror of the previous test: `build` kind MUST be followed.
    let build_only = r#"{
      "packages": [
        {"id": "path+file:///repo/pgp-core#0.1.0", "name": "pgp-core", "version": "0.1.0"},
        {"id": "registry+https://x#rand_core@0.9.5", "name": "rand_core", "version": "0.9.5"}
      ],
      "resolve": {
        "root": "path+file:///repo/pgp-core#0.1.0",
        "nodes": [
          {"id": "path+file:///repo/pgp-core#0.1.0", "deps": [
            {"pkg": "registry+https://x#rand_core@0.9.5", "dep_kinds": [{"kind": "build"}]}
          ]},
          {"id": "registry+https://x#rand_core@0.9.5", "deps": []}
        ]
      }
    }"#;
    let problems = forbidden_reachable(build_only).expect("graph check should run");
    assert_eq!(problems.len(), 1, "build-kind edge must be followed: {problems:?}");
}

#[test]
fn graph_mutation_missing_resolve_root_is_a_clean_error_not_a_panic() {
    let malformed = r#"{"packages": [], "resolve": {"nodes": []}}"#;
    let err = forbidden_reachable(malformed).unwrap_err();
    assert!(err.contains("resolve.root"), "{err}");
}

// --- the real graph, both real targets ---

/// Locate a `nix` executable without assuming the ambient shell has already
/// sourced the multi-user daemon's profile script (see the workspace
/// CLAUDE.md "Environment / toolchain" section: a non-login shell needs
/// `. '/nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh'` first).
/// Tries PATH, then the standard multi-user install location.
fn nix_binary() -> String {
    if Command::new("nix").arg("--version").output().is_ok_and(|o| o.status.success()) {
        return "nix".to_string();
    }
    const FALLBACK: &str = "/nix/var/nix/profiles/default/bin/nix";
    if Path::new(FALLBACK).exists() {
        return FALLBACK.to_string();
    }
    panic!(
        "no `nix` executable found on PATH or at {FALLBACK} — the device-target dependency \
         graph check needs the Foundation SDK's Nix shell (see below), which needs Nix itself"
    );
}

/// `cargo metadata --filter-platform` makes cargo ask rustc about the
/// target. For the KeyOS device target that query only succeeds through the
/// Foundation SDK's Nix-provided nightly rustc: `armv7a-unknown-xous-elf` is
/// a patched-in target that toolchain treats as "custom" (gated behind
/// `-Zunstable-options`, which nightly accepts natively) — verified against
/// `foundation`'s own embedded RUSTFLAGS for real hardware builds, which
/// carries the same flag. The standalone rustup toolchain that plain `cargo
/// test -p pgp-core` runs under doesn't know this target exists at all
/// (`rustc --print target-list` has no `armv7a-unknown-xous-elf` entry
/// there), so passing `-Zunstable-options` to IT just trades "unknown
/// target" for "the option `Z` is only accepted on the nightly compiler" —
/// confirmed empirically, both ways, while fixing this test after the SDK
/// 1.0.0 toolchain bump. So the device-target call is routed through
/// `nix develop <sdk root> --command cargo metadata ...` instead of the
/// ambient `cargo`; the host-target twin below is unaffected and keeps
/// using the ambient toolchain (its target is a rustc builtin everywhere).
fn cargo_metadata_json(target_triple: &str) -> String {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");

    if target_triple == DEVICE_TARGET {
        // Only trust FOUNDATION_SDK_ROOT when it really is the SDK checkout
        // (has a flake.nix). Running this test the documented way — `nix
        // develop <sdk> --command cargo test` — puts us inside the SDK shell,
        // which exports that variable pointing at the current PROJECT. Using
        // it then shells into a flake-less directory and the guard fails with
        // "is not part of a flake", which reads like a broken check rather
        // than a bad path (2026-08-27).
        let sdk_root = std::env::var("FOUNDATION_SDK_ROOT")
            .ok()
            .filter(|p| std::path::Path::new(p).join("flake.nix").exists())
            .unwrap_or_else(|| {
                let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
                format!("{home}/.foundation/sdk/current")
            });
        let nix = nix_binary();
        let out = Command::new(&nix)
            .args(["develop", &sdk_root, "--command", "cargo", "metadata", "--format-version", "1", "--filter-platform", target_triple, "--manifest-path"])
            .arg(&manifest)
            // Scoped to this one metadata call on purpose: exporting
            // -Zunstable-options for real builds' RUSTFLAGS is `foundation`'s
            // job (it already does this), not this test's.
            .env("RUSTFLAGS", "-Zunstable-options")
            .output()
            .unwrap_or_else(|e| {
                panic!(
                    "failed to run `{nix} develop {sdk_root} --command cargo metadata` for the \
                     device target: {e}\n\nThis check needs the Foundation SDK's Nix shell — run \
                     `foundation doctor` and make sure `nix develop {sdk_root}` works on its own \
                     first."
                )
            });
        assert!(
            out.status.success(),
            "`nix develop {sdk_root} --command cargo metadata --filter-platform {target_triple}` \
             failed:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let stdout = String::from_utf8(out.stdout).expect("cargo metadata output was not UTF-8");
        // The SDK's Nix flake prints a "Foundation SDK user shell ready."
        // banner via its shellHook, onto stdout, ahead of the real command's
        // own output — `nix develop --command` doesn't suppress it. The
        // metadata document itself always starts with `{`, so trim anything
        // the shell hook printed before it rather than fighting the hook.
        return match stdout.find('{') {
            Some(idx) => stdout[idx..].to_string(),
            None => panic!("no JSON object found in `nix develop` output:\n{stdout}"),
        };
    }

    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let out = Command::new(&cargo)
        .args(["metadata", "--format-version", "1", "--filter-platform", target_triple, "--manifest-path"])
        .arg(&manifest)
        .output()
        .unwrap_or_else(|e| panic!("failed to run `{cargo} metadata`: {e}"));
    assert!(
        out.status.success(),
        "`cargo metadata --filter-platform {target_triple}` failed:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).expect("cargo metadata output was not UTF-8")
}

fn host_triple() -> String {
    let out = Command::new("rustc").arg("-vV").output().expect("run `rustc -vV`");
    let text = String::from_utf8_lossy(&out.stdout);
    text.lines()
        .find_map(|l| l.strip_prefix("host: "))
        .unwrap_or_else(|| panic!("no `host:` line in `rustc -vV` output:\n{text}"))
        .trim()
        .to_string()
}

/// The one hardware target this workspace ships to (see workspace
/// CLAUDE.md's done-command: `cargo check --target
/// armv7a-unknown-xous-elf`).
const DEVICE_TARGET: &str = "armv7a-unknown-xous-elf";

#[test]
fn dependency_graph_reaches_only_the_patched_getrandom_on_host() {
    let host = host_triple();
    let json = cargo_metadata_json(&host);
    let problems = forbidden_reachable(&json).expect("graph check itself failed to parse real metadata");
    assert!(
        problems.is_empty(),
        "entropy supply-chain guard tripped for target {host}:\n\n{}",
        problems.join("\n\n")
    );
}

#[test]
fn dependency_graph_reaches_only_the_patched_getrandom_on_device_target() {
    let json = cargo_metadata_json(DEVICE_TARGET);
    let problems = forbidden_reachable(&json).expect("graph check itself failed to parse real metadata");
    assert!(
        problems.is_empty(),
        "entropy supply-chain guard tripped for target {DEVICE_TARGET}:\n\n{}",
        problems.join("\n\n")
    );
}
