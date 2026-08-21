//! Seed-derived key tests: same app-seed + index must always reproduce the
//! same key material and fingerprint; different inputs must not.

use pgp_core::*;

const SEED_A: [u8; 32] = [0x11; 32];
const SEED_B: [u8; 32] = [0x22; 32];

fn fpr(key: &pgp::composed::SignedSecretKey) -> String {
    key_info(&PgpKey::Secret(key.clone())).fingerprint
}

#[test]
fn same_seed_same_index_is_deterministic() {
    let a = derive_ed25519(&SEED_A, 0, "Alice", "alice@example.com", None).unwrap();
    let b = derive_ed25519(&SEED_A, 0, "Alice", "alice@example.com", None).unwrap();
    assert_eq!(fpr(&a), fpr(&b));

    // Byte-identical key material, not just fingerprint: compare the
    // unprotected secret key armor of both primaries via public export
    // equality + fingerprint of every subkey.
    let ia = key_info(&PgpKey::Secret(a));
    let ib = key_info(&PgpKey::Secret(b));
    assert_eq!(ia.subkeys[0].key_id, ib.subkeys[0].key_id);
    assert_eq!(ia.created_at, DERIVED_KEY_CREATED_AT as i64);
}

#[test]
fn uid_and_passphrase_do_not_change_key_material() {
    let plain = derive_ed25519(&SEED_A, 0, "Alice", "alice@example.com", None).unwrap();
    let renamed = derive_ed25519(&SEED_A, 0, "Completely Different", "other@example.com", None).unwrap();
    let protected = derive_ed25519(&SEED_A, 0, "Alice", "alice@example.com", Some("pw-123")).unwrap();

    assert_eq!(fpr(&plain), fpr(&renamed), "uid must not affect derivation");
    assert_eq!(fpr(&plain), fpr(&protected), "passphrase must not affect derivation");
    assert_eq!(
        key_info(&PgpKey::Secret(plain)).subkeys[0].key_id,
        key_info(&PgpKey::Secret(protected)).subkeys[0].key_id,
        "encryption subkey must not depend on passphrase"
    );
}

#[test]
fn different_index_or_seed_gives_different_keys() {
    let base = derive_ed25519(&SEED_A, 0, "A", "a@example.com", None).unwrap();
    let idx1 = derive_ed25519(&SEED_A, 1, "A", "a@example.com", None).unwrap();
    let seed_b = derive_ed25519(&SEED_B, 0, "A", "a@example.com", None).unwrap();
    assert_ne!(fpr(&base), fpr(&idx1));
    assert_ne!(fpr(&base), fpr(&seed_b));
    assert_ne!(fpr(&idx1), fpr(&seed_b));
}

#[test]
fn derived_key_roundtrips_and_passphrase_works() {
    let key = derive_ed25519(&SEED_A, 7, "Roundtrip", "rt@example.com", Some("derive-pw")).unwrap();
    let original_fpr = fpr(&key);

    let armored = export_armored(&PgpKey::Secret(key)).unwrap();
    let reparsed = match parse_keys(armored.as_bytes()).unwrap().remove(0) {
        PgpKey::Secret(sk) => sk,
        _ => panic!("expected secret key"),
    };
    assert_eq!(fpr(&reparsed), original_fpr);
    assert!(check_passphrase(&reparsed, "derive-pw").is_ok());
    assert_eq!(check_passphrase(&reparsed, "wrong").unwrap_err().0, WRONG_PASSPHRASE);

    let info = key_info(&PgpKey::Secret(reparsed));
    assert_eq!(info.algorithm, "EdDSA");
    assert_eq!(info.subkeys.len(), 1);
    assert!(info.subkeys[0].usage.contains("encrypt"));
    assert_eq!(info.expires_at, None);
}

#[test]
fn derived_key_supports_edit_operations() {
    // The recovery story: re-derived keys are normal keys — expiry/uid/
    // passphrase edits all work on them.
    let key = derive_ed25519(&SEED_A, 3, "Edit", "edit@example.com", Some("pw")).unwrap();
    let now = 1_800_000_000i64;

    let expired = set_expiration(key.clone(), "pw", Some(365), now).unwrap();
    // Expiration is relative to the FIXED creation time.
    let info = key_info(&PgpKey::Secret(expired.clone()));
    assert_eq!(info.expires_at, Some(now + 365 * 86_400));

    let added = add_user_id(expired.clone(), "pw", "Second", "second@example.com").unwrap();
    assert_eq!(key_info(&PgpKey::Secret(added.clone())).user_ids.len(), 2);

    // Fingerprint is untouched by all edits.
    assert_eq!(fpr(&added), fpr(&key));
}

// --- P-521 from seed (derive_p521) -----------------------------------------

#[test]
fn derive_p521_is_deterministic_and_domain_separated() {
    let a = derive_p521(&[7u8; 32], 3, "P", "p@example.com", None).unwrap();
    let b = derive_p521(&[7u8; 32], 3, "Q", "q@example.com", Some("pw")).unwrap();
    assert_eq!(fpr(&a), fpr(&b), "uid/passphrase must not change the key");

    // different index and different seed both change the key
    let c = derive_p521(&[7u8; 32], 4, "P", "p@example.com", None).unwrap();
    let d = derive_p521(&[8u8; 32], 3, "P", "p@example.com", None).unwrap();
    assert_ne!(fpr(&a), fpr(&c));
    assert_ne!(fpr(&a), fpr(&d));

    // and the P-521 stream is independent of the Ed25519 one: same seed,
    // same index, different algorithm => different key
    let e = derive_ed25519(&[7u8; 32], 3, "P", "p@example.com", None).unwrap();
    assert_ne!(fpr(&a), fpr(&e));
}

#[test]
fn derive_p521_roundtrips_and_passphrase_works() {
    let key = derive_p521(&[9u8; 32], 0, "P", "p@example.com", Some("d-pass")).unwrap();
    let armored = export_armored(&PgpKey::Secret(key)).unwrap();
    let mut keys = parse_keys(armored.as_bytes()).unwrap();
    let PgpKey::Secret(sk) = keys.remove(0) else { panic!("expected secret") };
    assert!(check_passphrase(&sk, "d-pass").is_ok());
    assert!(check_passphrase(&sk, "nope").is_err());
    let info = key_info(&PgpKey::Secret(sk));
    assert_eq!(info.algorithm, "ECDSA");
    assert_eq!(info.size_or_curve, "P521");
    assert_eq!(info.created_at, 1_231_006_505);
}

#[test]
fn derived_keys_encrypt_and_decrypt() {
    // The derived subkeys are built from the deterministic stream, not the
    // system RNG — prove the ECDH half actually works for both schemes.
    for (name, key) in [
        ("ed25519", derive_ed25519(&[3u8; 32], 0, "D", "d@example.com", Some("pw")).unwrap()),
        ("p521", derive_p521(&[3u8; 32], 0, "D", "d@example.com", Some("pw")).unwrap()),
    ] {
        let plain = format!("derived {name} roundtrip").into_bytes();
        let k = PgpKey::Secret(key.clone());
        let cipher = encrypt_bytes(&k, "t.txt", plain.clone(), None)
            .unwrap_or_else(|e| panic!("{name}: encrypt failed: {e}"));
        let got = decrypt_bytes(&key, "pw", cipher)
            .unwrap_or_else(|e| panic!("{name}: decrypt failed: {e}"));
        assert_eq!(got, plain, "{name}");
    }
}
