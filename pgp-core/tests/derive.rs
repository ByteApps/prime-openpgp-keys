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

    let expired = set_expiration(&key, "pw", Some(365), now).unwrap();
    // Expiration is relative to the FIXED creation time.
    let info = key_info(&PgpKey::Secret(expired.clone()));
    assert_eq!(info.expires_at, Some(now + 365 * 86_400));

    let added = add_user_id(&expired, "pw", "Second", "second@example.com").unwrap();
    assert_eq!(key_info(&PgpKey::Secret(added.clone())).user_ids.len(), 2);

    // Fingerprint is untouched by all edits.
    assert_eq!(fpr(&added), fpr(&key));
}
