//! Cross-validation against a real GnuPG installation.
//!
//! Every test builds a throwaway GNUPGHOME and shells out to `gpg`; if no
//! gpg binary is found the tests print a notice and pass vacuously, so the
//! suite stays green on machines without GnuPG.

use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use pgp_core::*;

const PASS: &str = "fixture-pass";

fn gpg_bin() -> Option<PathBuf> {
    let candidates = [
        "/usr/local/MacGPG2/bin/gpg",
        "/opt/homebrew/bin/gpg",
        "/usr/local/bin/gpg",
        "/usr/bin/gpg",
    ];
    for c in candidates {
        if std::path::Path::new(c).exists() {
            return Some(PathBuf::from(c));
        }
    }
    // PATH lookup as a last resort
    let out = Command::new("sh").args(["-c", "command -v gpg"]).output().ok()?;
    if out.status.success() {
        let p = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if !p.is_empty() {
            return Some(PathBuf::from(p));
        }
    }
    None
}

struct Gpg {
    bin: PathBuf,
    home: PathBuf,
}

static HOME_SEQ: AtomicU32 = AtomicU32::new(0);

impl Gpg {
    fn new() -> Option<Self> {
        let bin = match gpg_bin() {
            Some(b) => b,
            None => {
                eprintln!("skipped: gpg not found");
                return None;
            }
        };
        let home = std::env::temp_dir().join(format!(
            "pgp-core-interop-{}-{}",
            std::process::id(),
            HOME_SEQ.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir_all(&home).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        Some(Gpg { bin, home })
    }

    fn run(&self, args: &[&str], stdin: &[u8]) -> (bool, String, String) {
        use std::io::Write;
        let mut cmd = Command::new(&self.bin);
        cmd.env("GNUPGHOME", &self.home)
            .args(["--batch", "--no-tty", "--pinentry-mode", "loopback"])
            .args(args)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        let mut child = cmd.spawn().unwrap();
        child.stdin.as_mut().unwrap().write_all(stdin).unwrap();
        let out = child.wait_with_output().unwrap();
        (
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    }

    fn import(&self, armored: &str) {
        let (ok, _, err) = self.run(&["--import"], armored.as_bytes());
        assert!(ok, "gpg --import failed: {err}");
    }

    /// (record-type, field-index) values from --with-colons output.
    fn colons(&self, args: &[&str]) -> Vec<Vec<String>> {
        let (ok, out, err) = self.run(args, b"");
        assert!(ok, "gpg {args:?} failed: {err}");
        out.lines()
            .map(|l| l.split(':').map(str::to_string).collect())
            .collect()
    }
}

impl Drop for Gpg {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.home);
    }
}

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()
}

fn fixture_secret(name: &str) -> pgp::composed::SignedSecretKey {
    match parse_keys(&fixture(name)).unwrap().remove(0) {
        PgpKey::Secret(sk) => sk,
        _ => panic!("expected secret key"),
    }
}

fn now_epoch() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
}

// ---------------------------------------------------------------------------

#[test]
fn gpg_imports_our_generated_key() {
    let Some(gpg) = Gpg::new() else { return };

    let key = generate_rsa(2048, "Interop Gen", "interop-gen@example.com", Some("s3cret")).unwrap();
    let info = key_info(&PgpKey::Secret(key.clone()));

    gpg.import(&export_public_armored(&PgpKey::Secret(key.clone())).unwrap());
    gpg.import(&export_armored(&PgpKey::Secret(key)).unwrap());

    let pub_recs = gpg.colons(&["--list-keys", "--with-colons"]);
    let fprs: Vec<&str> = pub_recs
        .iter()
        .filter(|r| r[0] == "fpr")
        .map(|r| r[9].as_str())
        .collect();
    assert!(fprs.contains(&info.fingerprint.as_str()), "fingerprint not in gpg keyring");

    let sec_recs = gpg.colons(&["--list-secret-keys", "--with-colons"]);
    assert!(
        sec_recs.iter().any(|r| r[0] == "fpr" && r[9] == info.fingerprint),
        "secret key not in gpg keyring"
    );

    // self-signatures must verify from gpg's point of view
    let (ok, out, err) = gpg.run(&["--check-sigs", "--with-colons", &info.fingerprint], b"");
    assert!(ok, "--check-sigs failed: {err}");
    assert!(out.lines().any(|l| l.starts_with("sig:!")), "no valid self-sig: {out}");

    // and gpg can actually sign with the imported secret key + passphrase
    let (ok, _, err) = gpg.run(
        &["--passphrase", "s3cret", "--local-user", &info.fingerprint, "--sign", "--output", "/dev/null"],
        b"payload",
    );
    assert!(ok, "gpg --sign with our key failed: {err}");
}

#[test]
fn gpg_sees_extended_expiration() {
    let Some(gpg) = Gpg::new() else { return };

    let sk = fixture_secret("rsa2048-secret.asc");
    let now = now_epoch();
    let edited = set_expiration(&sk, PASS, Some(365), now).unwrap();
    let info = key_info(&PgpKey::Secret(edited.clone()));

    gpg.import(&export_armored(&PgpKey::Secret(edited)).unwrap());

    let recs = gpg.colons(&["--list-keys", "--with-colons", &info.fingerprint]);
    let pub_rec = recs.iter().find(|r| r[0] == "pub").expect("no pub record");
    let gpg_expiry: i64 = pub_rec[6].parse().expect("gpg reports no expiration");
    let want = now + 365 * 86_400;
    assert!(
        (gpg_expiry - want).abs() <= 2 * 86_400,
        "gpg expiry {gpg_expiry} not within 2 days of {want}"
    );
}

#[test]
fn gpg_sees_added_user_id() {
    let Some(gpg) = Gpg::new() else { return };

    let sk = fixture_secret("rsa2048-secret.asc");
    let edited = add_user_id(&sk, PASS, "Interop Uid", "interop-uid@example.com").unwrap();
    let info = key_info(&PgpKey::Secret(edited.clone()));

    gpg.import(&export_armored(&PgpKey::Secret(edited)).unwrap());

    let recs = gpg.colons(&["--list-keys", "--with-colons", &info.fingerprint]);
    let uids: Vec<&str> = recs
        .iter()
        .filter(|r| r[0] == "uid")
        .map(|r| r[9].as_str())
        .collect();
    assert_eq!(uids.len(), 2, "gpg should list both user IDs: {uids:?}");
    assert!(uids.iter().any(|u| u.contains("interop-uid@example.com")));

    // both uids carry valid self-sigs
    let (ok, out, err) = gpg.run(&["--check-sigs", "--with-colons", &info.fingerprint], b"");
    assert!(ok, "--check-sigs failed: {err}");
    let valid_sigs = out.lines().filter(|l| l.starts_with("sig:!")).count();
    assert!(valid_sigs >= 2, "expected self-sigs on both uids: {out}");
}

#[test]
fn gpg_signs_after_our_passphrase_change() {
    let Some(gpg) = Gpg::new() else { return };

    let sk = fixture_secret("rsa2048-secret.asc");
    let changed = change_passphrase(&sk, PASS, Some("rotated-pass")).unwrap();
    let info = key_info(&PgpKey::Secret(changed.clone()));

    gpg.import(&export_armored(&PgpKey::Secret(changed)).unwrap());

    // Old passphrase first (gpg-agent caches a successful unlock, so testing
    // the failure case after a success would hit the cache and pass).
    let (ok, _, _) = gpg.run(
        &["--passphrase", PASS, "--local-user", &info.fingerprint, "--sign", "--output", "/dev/null"],
        b"payload",
    );
    assert!(!ok, "old passphrase unexpectedly still works in gpg");

    // new passphrase unlocks the key inside gpg (validates our S2K output)
    let (ok, _, err) = gpg.run(
        &["--passphrase", "rotated-pass", "--local-user", &info.fingerprint, "--sign", "--output", "/dev/null"],
        b"payload",
    );
    assert!(ok, "gpg --sign with rotated passphrase failed: {err}");
}

#[test]
fn our_edited_armor_is_packet_clean() {
    let Some(gpg) = Gpg::new() else { return };

    let sk = fixture_secret("rsa2048-secret.asc");
    let edited = add_user_id(
        &set_expiration(&sk, PASS, Some(30), now_epoch()).unwrap(),
        PASS,
        "Packet Clean",
        "packets@example.com",
    )
    .unwrap();
    let armored = export_armored(&PgpKey::Secret(edited)).unwrap();

    let (ok, _, err) = gpg.run(&["--list-packets"], armored.as_bytes());
    assert!(ok, "gpg --list-packets rejected our armor: {err}");
}

#[test]
fn gpg_accepts_seed_derived_key() {
    let Some(gpg) = Gpg::new() else { return };

    let key = derive_ed25519(&[0x42; 32], 0, "Derived Interop", "derived@example.com", Some("d-pass"))
        .unwrap();
    let info = key_info(&PgpKey::Secret(key.clone()));

    gpg.import(&export_armored(&PgpKey::Secret(key)).unwrap());

    let recs = gpg.colons(&["--list-secret-keys", "--with-colons", &info.fingerprint]);
    assert!(recs.iter().any(|r| r[0] == "fpr" && r[9] == info.fingerprint));

    let (ok, out, err) = gpg.run(&["--check-sigs", "--with-colons", &info.fingerprint], b"");
    assert!(ok, "--check-sigs failed: {err}");
    assert!(out.lines().any(|l| l.starts_with("sig:!")), "no valid self-sig: {out}");

    let (ok, _, err) = gpg.run(
        &["--passphrase", "d-pass", "--local-user", &info.fingerprint, "--sign", "--output", "/dev/null"],
        b"payload",
    );
    assert!(ok, "gpg --sign with derived key failed: {err}");
}

#[test]
fn gpg_verifies_our_detached_signature() {
    let Some(gpg) = Gpg::new() else { return };

    for name in ["rsa2048-secret.asc", "ed25519-cv25519-secret.asc"] {
        let sk = fixture_secret(name);
        gpg.import(&export_public_armored(&PgpKey::Secret(sk.clone())).unwrap());

        let data = b"interop payload\n";
        let sig = sign_detached(&sk, PASS, data).unwrap();

        let data_path = gpg.home.join(format!("{name}.payload"));
        let sig_path = gpg.home.join(format!("{name}.payload.sig"));
        std::fs::write(&data_path, data).unwrap();
        std::fs::write(&sig_path, &sig).unwrap();

        let (ok, out, err) = gpg.run(
            &[
                "--status-fd",
                "1",
                "--verify",
                sig_path.to_str().unwrap(),
                data_path.to_str().unwrap(),
            ],
            b"",
        );
        assert!(ok && out.contains("GOODSIG"), "{name}: gpg --verify failed: {out}{err}");

        // tampered payload must fail verification
        std::fs::write(&data_path, b"interop payload tampered\n").unwrap();
        let (ok, _, _) = gpg.run(
            &["--verify", sig_path.to_str().unwrap(), data_path.to_str().unwrap()],
            b"",
        );
        assert!(!ok, "{name}: gpg accepted a tampered payload");

        // the armored form (QR-friendly) must verify identically
        std::fs::write(&data_path, data).unwrap();
        let armored = sign_detached_armored(&sk, PASS, data).unwrap();
        let asc_path = gpg.home.join(format!("{name}.payload.asc"));
        std::fs::write(&asc_path, armored.as_bytes()).unwrap();
        let (ok, out, err) = gpg.run(
            &[
                "--status-fd",
                "1",
                "--verify",
                asc_path.to_str().unwrap(),
                data_path.to_str().unwrap(),
            ],
            b"",
        );
        assert!(ok && out.contains("GOODSIG"), "{name}: armored verify failed: {out}{err}");
    }
}

#[test]
fn we_import_every_gpg_generated_algorithm() {
    // The reverse direction of the interop story: keys born in gpg parse
    // through pgp-core. (No gpg needed at runtime — fixtures are committed —
    // but kept here since it is the counterpart of the export tests.)
    for name in ["rsa2048", "rsa4096", "dsa-elgamal", "ed25519-cv25519", "nistp256"] {
        for variant in ["public", "secret"] {
            let keys = parse_keys(&fixture(&format!("{name}-{variant}.asc"))).unwrap();
            assert_eq!(keys.len(), 1, "{name}-{variant}");
        }
    }
}
