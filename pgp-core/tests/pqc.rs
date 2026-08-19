//! RFC 9980 post-quantum checks (rpgp `draft-pqc` feature).
//!
//! The one PQC shape that stays a v4 key — and therefore coexists with the
//! rest of this app's v4 world — is an ML-KEM-768+X25519 ENCRYPTION subkey
//! (RFC 9980 allows algorithm 35 on v4 keys; the ML-DSA/SLH-DSA signature
//! algorithms are v6-only and out of scope here).
//!
//! There is deliberately NO GnuPG interop here, and it is not a version
//! problem: GnuPG (verified against 2.5.21, 2026-08-19) implements the
//! rival LibrePGP Kyber — its subkeys carry public-key algorithm ID 8,
//! not RFC 9980's 35 — so each side drops the other's PQC subkey as
//! unknown, BY DESIGN of the two specs. The cross-implementation peer is
//! Sequoia (`sq`, sequoia-openpgp >= 2.x), which speaks RFC 9980; the
//! interop test below skips cleanly when no sq binary is installed.

use pgp_core::*;

#[test]
fn mlkem768_x25519_subkey_roundtrips() {
    let key = generate_pqc_hybrid("PQC Hybrid", "pqc@example.com", None).unwrap();
    let armored = export_armored(&PgpKey::Secret(key)).unwrap();
    let mut keys = parse_keys(armored.as_bytes()).unwrap();
    assert_eq!(keys.len(), 1);
    let k = keys.remove(0);
    let info = key_info(&k);
    assert!(info.has_secret);
    assert_eq!(info.subkeys.len(), 1);

    let plain = b"post-quantum sealed".to_vec();
    let cipher = encrypt_bytes(&k, "t.txt", plain.clone(), None).unwrap();
    if let PgpKey::Secret(sk) = &k {
        assert_eq!(decrypt_bytes(sk, "", cipher).unwrap(), plain);
    } else {
        panic!("expected secret");
    }
}

#[test]
fn pqc_hybrid_passphrase_protects_and_signs() {
    let key = generate_pqc_hybrid("PQC Pass", "pqc-pass@example.com", Some("pq-pass")).unwrap();
    let armored = export_armored(&PgpKey::Secret(key)).unwrap();
    let mut keys = parse_keys(armored.as_bytes()).unwrap();
    let PgpKey::Secret(sk) = keys.remove(0) else { panic!("expected secret") };
    assert!(check_passphrase(&sk, "pq-pass").is_ok());
    assert!(check_passphrase(&sk, "wrong").is_err());

    // classical primary still signs
    let data = b"hybrid signed";
    let sig = sign_detached(&sk, "pq-pass", data).unwrap();
    use pgp::composed::{Deserializable, DetachedSignature};
    DetachedSignature::from_bytes(&sig[..])
        .unwrap()
        .verify(&sk.primary_key.public_key(), data)
        .unwrap();

    // and the PQC subkey decrypts under the passphrase
    let k = PgpKey::Secret(sk.clone());
    let cipher = encrypt_bytes(&k, "t.txt", data.to_vec(), None).unwrap();
    assert_eq!(decrypt_bytes(&sk, "pq-pass", cipher).unwrap(), data);
}

// ---------------------------------------------------------------------------
// Cross-implementation interop: Sequoia (RFC 9980 peer)
// ---------------------------------------------------------------------------

fn sq_bin() -> Option<std::path::PathBuf> {
    for cand in ["/opt/homebrew/bin/sq", "/usr/local/bin/sq"] {
        let p = std::path::PathBuf::from(cand);
        if p.is_file() {
            return Some(p);
        }
    }
    let out = std::process::Command::new("sh")
        .args(["-c", "command -v sq"])
        .output()
        .ok()?;
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if out.status.success() && !s.is_empty() {
        Some(s.into())
    } else {
        None
    }
}

#[test]
fn sequoia_encrypts_mlkem768_both_directions() {
    let Some(sq) = sq_bin() else {
        eprintln!("skipped: sq (Sequoia) not found");
        return;
    };
    let home = std::env::temp_dir().join(format!("sq-pqc-interop-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&home);
    std::fs::create_dir_all(&home).unwrap();
    let run = |args: &[&str], stdin_file: Option<&std::path::Path>| {
        let mut cmd = std::process::Command::new(&sq);
        cmd.arg("--home").arg(&home).args(args);
        if let Some(f) = stdin_file {
            cmd.stdin(std::fs::File::open(f).unwrap());
        }
        let out = cmd.output().expect("sq failed to run");
        (
            out.status.success(),
            out.stdout,
            String::from_utf8_lossy(&out.stderr).to_string(),
        )
    };

    let key = generate_pqc_hybrid("Sq Interop", "sq-pqc@example.com", None).unwrap();
    let info = key_info(&PgpKey::Secret(key.clone()));
    let key_path = home.join("key.asc");
    std::fs::write(&key_path, export_armored(&PgpKey::Secret(key.clone())).unwrap()).unwrap();

    let (ok, _, err) = run(&["key", "import", key_path.to_str().unwrap()], None);
    assert!(ok, "sq key import failed: {err}");
    let (ok, _, err) = run(
        &["pki", "link", "authorize", "--unconstrained", &format!("--cert={}", info.fingerprint), "--all"],
        None,
    );
    assert!(ok, "sq pki link authorize failed: {err}");

    // sq encrypts to the ML-KEM-768+X25519 subkey -> rpgp decrypts
    let plain = b"sq sealed this for rpgp\n";
    let plain_path = home.join("plain.txt");
    let cipher_path = home.join("cipher.pgp");
    std::fs::write(&plain_path, plain).unwrap();
    let (ok, _, err) = run(
        &["encrypt", "--for-email", "sq-pqc@example.com", "--without-signature",
          "--output", cipher_path.to_str().unwrap(), plain_path.to_str().unwrap()],
        None,
    );
    assert!(ok, "sq encrypt failed: {err}");
    let got = decrypt_bytes(&key, "", std::fs::read(&cipher_path).unwrap())
        .expect("rpgp failed to decrypt sq's ML-KEM message");
    assert_eq!(got, plain);

    // rpgp encrypts -> sq decrypts
    let ours = encrypt_bytes(&PgpKey::Secret(key.clone()), "t.txt", plain.to_vec(), None).unwrap();
    let ours_path = home.join("ours.pgp");
    std::fs::write(&ours_path, &ours).unwrap();
    let (ok, out, err) = run(&["decrypt", ours_path.to_str().unwrap()], None);
    assert!(ok, "sq decrypt of our message failed: {err}");
    assert_eq!(out, plain, "sq-decrypted plaintext mismatch");

    let _ = std::fs::remove_dir_all(&home);
}
