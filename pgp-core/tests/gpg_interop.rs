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
fn gpg_encrypts_we_decrypt() {
    let Some(gpg) = Gpg::new() else { return };

    let sk = fixture_secret("rsa2048-secret.asc");
    let info = key_info(&PgpKey::Secret(sk.clone()));
    gpg.import(&export_public_armored(&PgpKey::Secret(sk.clone())).unwrap());

    let plain = b"gpg encrypted this for us\n";
    let src = gpg.home.join("plain.txt");
    std::fs::write(&src, plain).unwrap();

    // Binary (-e) and armored (-ea): decrypt_bytes must accept both.
    for (flags, out_name) in [(vec!["-e"], "c.gpg"), (vec!["-e", "-a"], "c.asc")] {
        let out = gpg.home.join(out_name);
        let mut args = vec!["--yes", "--trust-model", "always", "-r", info.key_id.as_str()];
        args.extend(flags.iter().copied());
        args.extend(["--output", out.to_str().unwrap(), src.to_str().unwrap()]);
        let (ok, _, err) = gpg.run(&args, b"");
        assert!(ok, "gpg encrypt ({out_name}) failed: {err}");

        let cipher = std::fs::read(&out).unwrap();
        let got = decrypt_bytes(&sk, PASS, cipher)
            .unwrap_or_else(|e| panic!("decrypt of gpg {out_name} failed: {e}"));
        assert_eq!(got, plain, "{out_name}: plaintext mismatch");
    }
}

#[test]
fn we_encrypt_gpg_decrypts() {
    let Some(gpg) = Gpg::new() else { return };

    let sk = fixture_secret("rsa2048-secret.asc");
    gpg.import(&export_armored(&PgpKey::Secret(sk.clone())).unwrap());

    let plain = b"we encrypted this for gpg\n".to_vec();
    let cipher = encrypt_bytes(&PgpKey::Secret(sk.clone()), "t.txt", plain.clone(), None).unwrap();
    let enc_path = gpg.home.join("ours.gpg");
    std::fs::write(&enc_path, &cipher).unwrap();

    let (ok, out, err) = gpg.run(
        &["--passphrase", PASS, "--decrypt", enc_path.to_str().unwrap()],
        b"",
    );
    assert!(ok, "gpg -d of our message failed: {err}");
    assert_eq!(out.as_bytes(), &plain[..], "gpg-decrypted plaintext mismatch");
}

#[test]
fn we_sign_encrypt_gpg_goodsig() {
    let Some(gpg) = Gpg::new() else { return };

    let sk = fixture_secret("ed25519-cv25519-secret.asc");
    gpg.import(&export_armored(&PgpKey::Secret(sk.clone())).unwrap());

    let plain = b"signed inside the envelope\n".to_vec();
    let cipher = encrypt_bytes(
        &PgpKey::Secret(sk.clone()),
        "t.txt",
        plain.clone(),
        Some((&sk, PASS)),
    )
    .unwrap();
    let enc_path = gpg.home.join("ours-se.gpg");
    std::fs::write(&enc_path, &cipher).unwrap();

    let (ok, out, err) = gpg.run(
        &["--passphrase", PASS, "--status-fd", "1", "--decrypt", enc_path.to_str().unwrap()],
        b"",
    );
    assert!(ok, "gpg -d of our signed+encrypted message failed: {err}");
    assert!(out.contains("GOODSIG"), "no GOODSIG in gpg output: {out}");
    assert!(
        out.contains("signed inside the envelope"),
        "plaintext missing from gpg output: {out}"
    );
}

#[test]
fn we_import_every_gpg_generated_algorithm() {
    // The reverse direction of the interop story: keys born in gpg parse
    // through pgp-core. (No gpg needed at runtime — fixtures are committed —
    // but kept here since it is the counterpart of the export tests.)
    for name in ["rsa2048", "rsa4096", "dsa-elgamal", "ed25519-cv25519", "nistp256", "nistp521"] {
        for variant in ["public", "secret"] {
            let keys = parse_keys(&fixture(&format!("{name}-{variant}.asc"))).unwrap();
            assert_eq!(keys.len(), 1, "{name}-{variant}");
        }
    }
}

// ---------------------------------------------------------------------------
// NIST P-521 ("strongest classical" tier) — generated keys, both directions
// ---------------------------------------------------------------------------

#[test]
fn gpg_imports_our_p521_key() {
    let Some(gpg) = Gpg::new() else { return };

    let key = generate_p521("P521 Interop", "p521@example.com", Some("s3cret")).unwrap();
    let info = key_info(&PgpKey::Secret(key.clone()));

    gpg.import(&export_public_armored(&PgpKey::Secret(key.clone())).unwrap());
    gpg.import(&export_armored(&PgpKey::Secret(key)).unwrap());

    let sec_recs = gpg.colons(&["--list-secret-keys", "--with-colons"]);
    assert!(
        sec_recs.iter().any(|r| r[0] == "fpr" && r[9] == info.fingerprint),
        "secret key not in gpg keyring"
    );

    let (ok, out, err) = gpg.run(&["--check-sigs", "--with-colons", &info.fingerprint], b"");
    assert!(ok, "--check-sigs failed: {err}");
    assert!(out.lines().any(|l| l.starts_with("sig:!")), "no valid self-sig: {out}");

    let (ok, _, err) = gpg.run(
        &["--passphrase", "s3cret", "--local-user", &info.fingerprint, "--sign", "--output", "/dev/null"],
        b"payload",
    );
    assert!(ok, "gpg --sign with our P-521 key failed: {err}");
}

#[test]
fn gpg_verifies_our_p521_detached_signature() {
    let Some(gpg) = Gpg::new() else { return };

    let key = generate_p521("P521 Sig", "p521-sig@example.com", Some("s3cret")).unwrap();
    gpg.import(&export_public_armored(&PgpKey::Secret(key.clone())).unwrap());

    let data = b"p521 interop payload\n";
    let sig = sign_detached(&key, "s3cret", data).unwrap();

    let data_path = gpg.home.join("p521.payload");
    let sig_path = gpg.home.join("p521.payload.sig");
    std::fs::write(&data_path, data).unwrap();
    std::fs::write(&sig_path, &sig).unwrap();

    let (ok, out, err) = gpg.run(
        &["--status-fd", "1", "--verify", sig_path.to_str().unwrap(), data_path.to_str().unwrap()],
        b"",
    );
    assert!(ok && out.contains("GOODSIG"), "gpg --verify failed: {out}{err}");

    std::fs::write(&data_path, b"tampered\n").unwrap();
    let (ok, _, _) = gpg.run(
        &["--verify", sig_path.to_str().unwrap(), data_path.to_str().unwrap()],
        b"",
    );
    assert!(!ok, "gpg accepted a tampered payload");
}

#[test]
fn gpg_encrypts_p521_we_decrypt() {
    let Some(gpg) = Gpg::new() else { return };

    let key = generate_p521("P521 Dec", "p521-dec@example.com", Some("s3cret")).unwrap();
    let info = key_info(&PgpKey::Secret(key.clone()));
    gpg.import(&export_public_armored(&PgpKey::Secret(key.clone())).unwrap());

    let plain = b"gpg encrypted this to p521\n";
    let src = gpg.home.join("plain.txt");
    std::fs::write(&src, plain).unwrap();

    for (flags, out_name) in [(vec!["-e"], "c.gpg"), (vec!["-e", "-a"], "c.asc")] {
        let out = gpg.home.join(out_name);
        let mut args = vec!["--yes", "--trust-model", "always", "-r", info.key_id.as_str()];
        args.extend(flags.iter().copied());
        args.extend(["--output", out.to_str().unwrap(), src.to_str().unwrap()]);
        let (ok, _, err) = gpg.run(&args, b"");
        assert!(ok, "gpg encrypt ({out_name}) failed: {err}");

        let cipher = std::fs::read(&out).unwrap();
        let got = decrypt_bytes(&key, "s3cret", cipher)
            .unwrap_or_else(|e| panic!("decrypt of gpg {out_name} failed: {e}"));
        assert_eq!(got, plain, "{out_name}: plaintext mismatch");
    }
}

#[test]
fn we_encrypt_p521_gpg_decrypts() {
    let Some(gpg) = Gpg::new() else { return };

    let key = generate_p521("P521 Enc", "p521-enc@example.com", Some("s3cret")).unwrap();
    gpg.import(&export_armored(&PgpKey::Secret(key.clone())).unwrap());

    let plain = b"we encrypted this to p521 for gpg\n".to_vec();
    let cipher = encrypt_bytes(&PgpKey::Secret(key.clone()), "t.txt", plain.clone(), None).unwrap();
    let enc_path = gpg.home.join("ours-p521.gpg");
    std::fs::write(&enc_path, &cipher).unwrap();

    let (ok, out, err) = gpg.run(
        &["--passphrase", "s3cret", "--decrypt", enc_path.to_str().unwrap()],
        b"",
    );
    assert!(ok, "gpg -d of our P-521 message failed: {err}");
    assert_eq!(out.as_bytes(), &plain[..], "gpg-decrypted plaintext mismatch");
}

#[test]
fn gpg_accepts_our_random_ed25519_key() {
    let Some(gpg) = Gpg::new() else { return };

    let key = generate_ed25519("Ed Interop", "ed-interop@example.com", Some("s3cret")).unwrap();
    let info = key_info(&PgpKey::Secret(key.clone()));
    gpg.import(&export_armored(&PgpKey::Secret(key)).unwrap());

    let (ok, out, err) = gpg.run(&["--check-sigs", "--with-colons", &info.fingerprint], b"");
    assert!(ok, "--check-sigs failed: {err}");
    assert!(out.lines().any(|l| l.starts_with("sig:!")), "no valid self-sig: {out}");

    let (ok, _, err) = gpg.run(
        &["--passphrase", "s3cret", "--local-user", &info.fingerprint, "--sign", "--output", "/dev/null"],
        b"payload",
    );
    assert!(ok, "gpg --sign with our random Ed25519 key failed: {err}");
}

#[test]
fn gpg_accepts_seed_derived_p521_key() {
    let Some(gpg) = Gpg::new() else { return };

    let key = derive_p521(&[0x42; 32], 0, "Derived P521", "derived-p521@example.com", Some("d-pass"))
        .unwrap();
    let info = key_info(&PgpKey::Secret(key.clone()));
    gpg.import(&export_armored(&PgpKey::Secret(key)).unwrap());

    let (ok, out, err) = gpg.run(&["--check-sigs", "--with-colons", &info.fingerprint], b"");
    assert!(ok, "--check-sigs failed: {err}");
    assert!(out.lines().any(|l| l.starts_with("sig:!")), "no valid self-sig: {out}");

    let (ok, _, err) = gpg.run(
        &["--passphrase", "d-pass", "--local-user", &info.fingerprint, "--sign", "--output", "/dev/null"],
        b"payload",
    );
    assert!(ok, "gpg --sign with derived P-521 key failed: {err}");
}

#[test]
fn gpg_accepts_our_p384_key() {
    let Some(gpg) = Gpg::new() else { return };

    let key = generate_nistp(NistCurve::P384, "P384 Interop", "p384@example.com", Some("s3cret")).unwrap();
    let info = key_info(&PgpKey::Secret(key.clone()));
    gpg.import(&export_armored(&PgpKey::Secret(key)).unwrap());

    let (ok, out, err) = gpg.run(&["--check-sigs", "--with-colons", &info.fingerprint], b"");
    assert!(ok, "--check-sigs failed: {err}");
    assert!(out.lines().any(|l| l.starts_with("sig:!")), "no valid self-sig: {out}");

    let (ok, _, err) = gpg.run(
        &["--passphrase", "s3cret", "--local-user", &info.fingerprint, "--sign", "--output", "/dev/null"],
        b"payload",
    );
    assert!(ok, "gpg --sign with our P-384 key failed: {err}");
}

#[test]
fn gpg_encrypts_all_nist_curves_we_decrypt_and_back() {
    let Some(gpg) = Gpg::new() else { return };

    for curve in [NistCurve::P256, NistCurve::P384, NistCurve::P521] {
        let name = format!("{curve:?}");
        let key = generate_nistp(curve, &name, &format!("{name}@example.com"), Some("s3cret")).unwrap();
        let info = key_info(&PgpKey::Secret(key.clone()));
        gpg.import(&export_armored(&PgpKey::Secret(key.clone())).unwrap());

        // gpg encrypts -> we decrypt
        let plain = format!("gpg sealed this to {name}\n").into_bytes();
        let src = gpg.home.join(format!("{name}.txt"));
        std::fs::write(&src, &plain).unwrap();
        let out = gpg.home.join(format!("{name}.gpg"));
        let (ok, _, err) = gpg.run(
            &["--yes", "--trust-model", "always", "-r", info.key_id.as_str(), "-e",
              "--output", out.to_str().unwrap(), src.to_str().unwrap()],
            b"",
        );
        assert!(ok, "{name}: gpg encrypt failed: {err}");
        let got = decrypt_bytes(&key, "s3cret", std::fs::read(&out).unwrap())
            .unwrap_or_else(|e| panic!("{name}: our decrypt failed: {e}"));
        assert_eq!(got, plain, "{name}");

        // we encrypt -> gpg decrypts
        let cipher =
            encrypt_bytes(&PgpKey::Secret(key.clone()), "t.txt", plain.clone(), None).unwrap();
        let enc = gpg.home.join(format!("{name}-ours.gpg"));
        std::fs::write(&enc, &cipher).unwrap();
        let (ok, out_txt, err) = gpg.run(
            &["--passphrase", "s3cret", "--decrypt", enc.to_str().unwrap()],
            b"",
        );
        assert!(ok, "{name}: gpg -d of our message failed: {err}");
        assert_eq!(out_txt.as_bytes(), &plain[..], "{name}: gpg plaintext mismatch");
    }
}
