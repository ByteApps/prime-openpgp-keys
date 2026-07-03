//! Round-trip and edit-operation tests over gpg-generated fixtures.
//!
//! Fixtures live in `tests/fixtures/` (see its README.md for the exact gpg
//! commands); every secret fixture is protected with passphrase
//! `fixture-pass`.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use pgp_core::*;

const PASS: &str = "fixture-pass";

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()
}

fn expected_fprs() -> HashMap<String, String> {
    String::from_utf8(fixture("expected_fprs.txt"))
        .unwrap()
        .lines()
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn parse_one(name: &str) -> PgpKey {
    let mut keys = parse_keys(&fixture(name)).unwrap();
    assert_eq!(keys.len(), 1, "{name} should contain exactly one key");
    keys.remove(0)
}

fn secret(name: &str) -> pgp::composed::SignedSecretKey {
    match parse_one(name) {
        PgpKey::Secret(sk) => sk,
        PgpKey::Public(_) => panic!("{name} unexpectedly public"),
    }
}

fn now_epoch() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

// ---------------------------------------------------------------------------
// Parsing across algorithms
// ---------------------------------------------------------------------------

struct Expected {
    algo: &'static str,
    size_or_curve: &'static str,
    sub_algo: &'static str,
}

fn check_fixture_pair(name: &str, exp: Expected) {
    let fprs = expected_fprs();
    let want_fpr = &fprs[name];

    for (file, has_secret) in [
        (format!("{name}-public.asc"), false),
        (format!("{name}-secret.asc"), true),
    ] {
        let key = parse_one(&file);
        let info = key_info(&key);
        assert_eq!(info.has_secret, has_secret, "{file}");
        assert_eq!(&info.fingerprint, want_fpr, "{file}");
        assert_eq!(info.algorithm, exp.algo, "{file}");
        assert_eq!(info.size_or_curve, exp.size_or_curve, "{file}");
        assert_eq!(info.expires_at, None, "{file} (fixtures never expire)");
        assert_eq!(
            info.user_ids,
            vec![format!("Fixture {name} <{name}@example.com>")],
            "{file}"
        );
        assert_eq!(info.subkeys.len(), 1, "{file}");
        assert_eq!(info.subkeys[0].algorithm, exp.sub_algo, "{file}");
        assert!(info.subkeys[0].usage.contains("encrypt"), "{file}");
        assert_eq!(info.key_id, want_fpr[want_fpr.len() - 16..], "{file}");
    }
}

#[test]
fn parse_rsa2048() {
    check_fixture_pair(
        "rsa2048",
        Expected { algo: "RSA", size_or_curve: "2048 bits", sub_algo: "RSA" },
    );
}

#[test]
fn parse_rsa4096() {
    check_fixture_pair(
        "rsa4096",
        Expected { algo: "RSA", size_or_curve: "4096 bits", sub_algo: "RSA" },
    );
}

#[test]
fn parse_dsa_elgamal() {
    check_fixture_pair(
        "dsa-elgamal",
        Expected { algo: "DSA", size_or_curve: "", sub_algo: "ElGamal" },
    );
}

#[test]
fn parse_ed25519_cv25519() {
    check_fixture_pair(
        "ed25519-cv25519",
        Expected { algo: "EdDSA", size_or_curve: "Curve25519", sub_algo: "ECDH" },
    );
}

#[test]
fn parse_nistp256() {
    check_fixture_pair(
        "nistp256",
        Expected { algo: "ECDSA", size_or_curve: "P256", sub_algo: "ECDH" },
    );
}

#[test]
fn parse_multiple_keys_in_one_file() {
    // Both real-world shapes: two concatenated armor blocks (cat a.asc
    // b.asc) and one armor block holding two keys (gpg --export k1 k2).
    for file in ["two-keys-concatenated.asc", "two-keys-single-block.asc"] {
        let keys = parse_keys(&fixture(file)).unwrap();
        assert_eq!(keys.len(), 2, "{file}");
        let fprs = expected_fprs();
        assert_eq!(key_info(&keys[0]).fingerprint, fprs["rsa2048"], "{file}");
        assert_eq!(key_info(&keys[1]).fingerprint, fprs["ed25519-cv25519"], "{file}");
    }
}

#[test]
fn parse_garbage_is_error() {
    assert!(parse_keys(&fixture("garbage.asc")).is_err());
    assert!(parse_keys(b"").is_err());
}

#[test]
fn parse_truncated_is_error() {
    assert!(parse_keys(&fixture("truncated.asc")).is_err());
}

// ---------------------------------------------------------------------------
// Generation
// ---------------------------------------------------------------------------

fn generate_roundtrip(bits: u32) {
    let key = generate_rsa(bits, "Gen Test", "gen@example.com", Some("gen-pass")).unwrap();
    let armored = export_armored(&PgpKey::Secret(key.clone())).unwrap();
    assert!(armored.starts_with("-----BEGIN PGP PRIVATE KEY BLOCK-----"));

    let reparsed = parse_one_bytes(armored.as_bytes());
    let info = key_info(&reparsed);
    assert!(info.has_secret);
    assert_eq!(info.algorithm, "RSA");
    assert_eq!(info.size_or_curve, format!("{bits} bits"));
    assert_eq!(info.user_ids, vec!["Gen Test <gen@example.com>".to_string()]);
    assert_eq!(info.expires_at, None);
    assert_eq!(info.subkeys.len(), 1);
    assert!(info.subkeys[0].usage.contains("encrypt"));

    // public export drops secret material but keeps identity
    let pub_armored = export_public_armored(&reparsed).unwrap();
    assert!(pub_armored.starts_with("-----BEGIN PGP PUBLIC KEY BLOCK-----"));
    let pub_key = parse_one_bytes(pub_armored.as_bytes());
    assert!(!pub_key.has_secret());
    assert_eq!(key_info(&pub_key).fingerprint, info.fingerprint);

    // the passphrase actually protects the reparsed key
    if let PgpKey::Secret(sk) = &reparsed {
        assert!(check_passphrase(sk, "gen-pass").is_ok());
        assert!(check_passphrase(sk, "not-it").is_err());
    }
}

fn parse_one_bytes(data: &[u8]) -> PgpKey {
    let mut keys = parse_keys(data).unwrap();
    assert_eq!(keys.len(), 1);
    keys.remove(0)
}

#[test]
fn generate_rsa2048_roundtrip() {
    generate_roundtrip(2048);
}

#[test]
#[ignore = "slow: RSA-3072 generation"]
fn generate_rsa3072_roundtrip() {
    generate_roundtrip(3072);
}

#[test]
#[ignore = "slow: RSA-4096 generation"]
fn generate_rsa4096_roundtrip() {
    generate_roundtrip(4096);
}

// ---------------------------------------------------------------------------
// Edit operations (parameterized across algorithms)
// ---------------------------------------------------------------------------

/// Secret fixtures whose primary key rpgp can sign with.
const EDITABLE: &[&str] = &["rsa2048", "ed25519-cv25519", "nistp256", "dsa-elgamal"];

#[test]
fn set_expiration_roundtrip_all_algorithms() {
    for name in EDITABLE {
        let sk = secret(&format!("{name}-secret.asc"));
        let now = now_epoch();

        let expired = set_expiration(&sk, PASS, Some(365), now).unwrap();
        let armored = export_armored(&PgpKey::Secret(expired)).unwrap();
        let info = key_info(&parse_one_bytes(armored.as_bytes()));
        let want = now + 365 * 86_400;
        let got = info
            .expires_at
            .unwrap_or_else(|| panic!("{name}: expiration not set"));
        assert!(
            (got - want).abs() <= 86_400,
            "{name}: expires_at {got} not within a day of {want}"
        );

        // and clear it again
        let sk2 = secret(&format!("{name}-secret.asc"));
        let cleared = set_expiration(&set_expiration(&sk2, PASS, Some(30), now).unwrap(), PASS, None, now)
            .unwrap();
        let armored = export_armored(&PgpKey::Secret(cleared)).unwrap();
        assert_eq!(
            key_info(&parse_one_bytes(armored.as_bytes())).expires_at,
            None,
            "{name}: expiration should be cleared"
        );
    }
}

#[test]
fn set_expiration_wrong_passphrase() {
    let sk = secret("rsa2048-secret.asc");
    let err = set_expiration(&sk, "wrong", Some(365), now_epoch()).unwrap_err();
    assert_eq!(err.0, WRONG_PASSPHRASE);
}

#[test]
fn add_and_remove_user_id_all_algorithms() {
    for name in EDITABLE {
        let sk = secret(&format!("{name}-secret.asc"));

        let added = add_user_id(&sk, PASS, "Second Identity", "second@example.com").unwrap();
        let armored = export_armored(&PgpKey::Secret(added.clone())).unwrap();
        let info = key_info(&parse_one_bytes(armored.as_bytes()));
        assert_eq!(info.user_ids.len(), 2, "{name}");
        assert!(
            info.user_ids
                .contains(&"Second Identity <second@example.com>".to_string()),
            "{name}"
        );

        let removed = remove_user_id(&added, 1).unwrap();
        let armored = export_armored(&PgpKey::Secret(removed.clone())).unwrap();
        let info = key_info(&parse_one_bytes(armored.as_bytes()));
        assert_eq!(info.user_ids.len(), 1, "{name}");

        // never allowed to drop the last one
        assert!(remove_user_id(&removed, 0).is_err(), "{name}");
    }
}

#[test]
fn add_user_id_preserves_expiration() {
    let sk = secret("rsa2048-secret.asc");
    let now = now_epoch();
    let expiring = set_expiration(&sk, PASS, Some(100), now).unwrap();
    let added = add_user_id(&expiring, PASS, "Third", "third@example.com").unwrap();
    let armored = export_armored(&PgpKey::Secret(added)).unwrap();
    let info = key_info(&parse_one_bytes(armored.as_bytes()));
    let got = info.expires_at.expect("expiration must survive add_user_id");
    assert!((got - (now + 100 * 86_400)).abs() <= 86_400);
}

#[test]
fn change_passphrase_all_algorithms() {
    for name in EDITABLE {
        let sk = secret(&format!("{name}-secret.asc"));

        let changed = change_passphrase(&sk, PASS, Some("brand-new-pass")).unwrap();
        let armored = export_armored(&PgpKey::Secret(changed)).unwrap();
        let reparsed = match parse_one_bytes(armored.as_bytes()) {
            PgpKey::Secret(sk) => sk,
            _ => unreachable!(),
        };
        assert!(check_passphrase(&reparsed, "brand-new-pass").is_ok(), "{name}");
        assert_eq!(
            check_passphrase(&reparsed, PASS).unwrap_err().0,
            WRONG_PASSPHRASE,
            "{name}: old passphrase must stop working"
        );

        // removing protection entirely
        let unprotected = change_passphrase(&reparsed, "brand-new-pass", None).unwrap();
        let armored = export_armored(&PgpKey::Secret(unprotected)).unwrap();
        let reparsed = match parse_one_bytes(armored.as_bytes()) {
            PgpKey::Secret(sk) => sk,
            _ => unreachable!(),
        };
        assert!(check_passphrase(&reparsed, "").is_ok(), "{name}");
    }
}

#[test]
fn change_passphrase_wrong_old() {
    let sk = secret("rsa2048-secret.asc");
    let err = change_passphrase(&sk, "wrong", Some("x")).unwrap_err();
    assert_eq!(err.0, WRONG_PASSPHRASE);
}

#[test]
fn edits_refused_without_secret_material() {
    // Sanity: the app only offers edits on secret keys; the library-level
    // parse still yields Public for public fixtures.
    assert!(!parse_one("rsa2048-public.asc").has_secret());
}

// ---------------------------------------------------------------------------
// Detached signing
// ---------------------------------------------------------------------------

#[test]
fn sign_detached_roundtrip_all_algorithms() {
    use pgp::composed::{Deserializable, DetachedSignature};

    for name in ["rsa2048", "rsa4096", "ed25519-cv25519", "nistp256"] {
        let sk = secret(&format!("{name}-secret.asc"));
        let data = b"detached signing payload";
        let sig_bytes = sign_detached(&sk, PASS, data).unwrap();

        // The output must be a bare binary signature packet, not armor.
        assert!(!sig_bytes.starts_with(b"-----"), "{name}: output is armored");

        let parsed = DetachedSignature::from_bytes(&sig_bytes[..])
            .unwrap_or_else(|e| panic!("{name}: unparseable signature: {e}"));
        parsed
            .verify(&sk.primary_key.public_key(), data)
            .unwrap_or_else(|e| panic!("{name}: signature does not verify: {e}"));
        parsed
            .verify(&sk.primary_key.public_key(), b"tampered payload")
            .expect_err(&format!("{name}: tampered data verified"));
    }
}

#[test]
fn sign_detached_wrong_passphrase() {
    let sk = secret("rsa2048-secret.asc");
    let err = sign_detached(&sk, "not-the-pass", b"data").unwrap_err();
    assert_eq!(err.0, WRONG_PASSPHRASE);
}

#[test]
fn sign_detached_armored_roundtrip() {
    use pgp::composed::{Deserializable, DetachedSignature};

    let sk = secret("ed25519-cv25519-secret.asc");
    let data = b"armored signing payload";
    let armored = sign_detached_armored(&sk, PASS, data).unwrap();

    assert!(armored.starts_with("-----BEGIN PGP SIGNATURE-----"));
    assert!(armored.trim_end().ends_with("-----END PGP SIGNATURE-----"));

    let (parsed, _) = DetachedSignature::from_string(&armored).unwrap();
    parsed.verify(&sk.primary_key.public_key(), data).unwrap();
    parsed
        .verify(&sk.primary_key.public_key(), b"tampered payload")
        .expect_err("tampered data verified");
}
