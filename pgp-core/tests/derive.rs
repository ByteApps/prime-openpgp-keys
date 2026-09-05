//! Seed-derived key tests (PLAN-openpgp-keys-import.md §2.3).
//!
//! `derive_ed25519`/`derive_p521` are a **cross-platform contract**: a
//! future desktop/mobile OpenPGP Keys app must derive byte-identical keys
//! from the same `root` + index, using nothing but the raw-bytes spec in
//! §2.3 — not "whatever rpgp's RNG-driven generator does" (the old scheme
//! this replaced, reproducible only by rpgp 0.20). The
//! `*_matches_independent_construction` tests below are the proof: they
//! recompute the same key material with `ed25519-dalek`/`x25519-dalek`/
//! `p521` directly, never touching rpgp's key-generation code, and assert
//! the public key material embedded in our derived key matches.

use hkdf::Hkdf;
use pgp::types::{
    EcdhPublicParams, EcdsaPublicParams, EddsaLegacyPublicParams, KeyDetails as _, PublicParams,
};
use pgp_core::*;
use sha2::Sha256;

const ROOT_A: [u8; 32] = [0x11; 32];
const ROOT_B: [u8; 32] = [0x22; 32];
/// Fixed root ID for tests that don't care about its value — only the
/// provenance-notation tests below assert on it specifically.
const ROOT_ID: [u8; 4] = [0xAA, 0xBB, 0xCC, 0xDD];

fn fpr(key: &pgp::composed::SignedSecretKey) -> String {
    key_info(&PgpKey::Secret(key.clone())).fingerprint
}

fn public_params(key: &pgp::composed::SignedSecretKey) -> &PublicParams {
    key.primary_key.public_params()
}

fn subkey_public_params(key: &pgp::composed::SignedSecretKey) -> &PublicParams {
    key.secret_subkeys[0].key.public_params()
}

// ---------------------------------------------------------------------
// 1. Determinism
// ---------------------------------------------------------------------

#[test]
fn same_seed_same_index_is_deterministic() {
    let a = derive_ed25519(&ROOT_A, &ROOT_ID, 0, "Alice", "alice@example.com", None).unwrap();
    let b = derive_ed25519(&ROOT_A, &ROOT_ID, 0, "Alice", "alice@example.com", None).unwrap();
    assert_eq!(fpr(&a), fpr(&b));

    // Byte-identical key material, not just fingerprint.
    let ia = key_info(&PgpKey::Secret(a));
    let ib = key_info(&PgpKey::Secret(b));
    assert_eq!(ia.subkeys[0].key_id, ib.subkeys[0].key_id);
    assert_eq!(ia.created_at, DERIVED_KEY_CREATED_AT as i64);
}

/// The self-signatures use a FIXED creation time (not `Timestamp::now()`),
/// so two derivations of the same root+index produce byte-identical armor —
/// the only source of variation left is the S2K passphrase salt, and this
/// test uses no passphrase, so there is none.
#[test]
fn same_seed_same_index_is_byte_identical_armor_ed25519() {
    let a = derive_ed25519(&ROOT_A, &ROOT_ID, 3, "Same", "same@example.com", None).unwrap();
    let b = derive_ed25519(&ROOT_A, &ROOT_ID, 3, "Same", "same@example.com", None).unwrap();
    assert_eq!(
        export_armored(&PgpKey::Secret(a)).unwrap(),
        export_armored(&PgpKey::Secret(b)).unwrap(),
        "no passphrase => nothing should differ between two derivations"
    );
}

/// NOT byte-identical armor, unlike the Ed25519 sibling above — and this is
/// NOT something this crate can fix. rpgp's P-521 ECDSA signing goes through
/// `p521::ecdsa::SigningKey`'s own `PrehashSigner` impl
/// (p521-0.13.3/src/ecdsa.rs:132-136), which signs via
/// `sign_prehash_with_rng(&mut OsRng, ..)` — a RANDOMIZED nonce `k`, not
/// RFC 6979 deterministic (unlike the generic `ecdsa::SigningKey<C>`, whose
/// `PrehashSigner` impl at ecdsa-0.16.9/src/signing.rs:152-165 IS RFC 6979
/// deterministic — P-521 just doesn't route through it). So every
/// self-signature and subkey-binding signature over a P-521 key gets fresh
/// random R/S bytes on every derivation, on top of the S2K salt. The KEY
/// MATERIAL (and therefore the fingerprint) is still byte-identical, which
/// is the property seed-derived recovery actually depends on.
#[test]
fn same_seed_same_index_p521_key_material_is_identical_armor_is_not() {
    let a = derive_p521(&ROOT_A, &ROOT_ID, 3, "Same", "same@example.com", None).unwrap();
    let b = derive_p521(&ROOT_A, &ROOT_ID, 3, "Same", "same@example.com", None).unwrap();
    assert_eq!(fpr(&a), fpr(&b));
    assert_eq!(public_params(&a), public_params(&b));
    assert_eq!(subkey_public_params(&a), subkey_public_params(&b));
    assert_ne!(
        export_armored(&PgpKey::Secret(a)).unwrap(),
        export_armored(&PgpKey::Secret(b)).unwrap(),
        "expected the two P-521 self-signatures to differ (randomized ECDSA \
         nonce) even with no passphrase — if this now passes, either rpgp \
         started using deterministic P-521 signing (update this test and \
         its comment) or something else regressed"
    );
}

/// With a passphrase, the ONLY difference between two derivations must be
/// the S2K-encrypted secret material (fresh salt each time) — never the
/// public key packets or the self-signatures.
#[test]
fn passphrase_only_changes_s2k_bytes() {
    let a = derive_ed25519(&ROOT_A, &ROOT_ID, 5, "Pw", "pw@example.com", Some("d-pass")).unwrap();
    let b = derive_ed25519(&ROOT_A, &ROOT_ID, 5, "Pw", "pw@example.com", Some("d-pass")).unwrap();
    let aa = export_armored(&PgpKey::Secret(a)).unwrap();
    let ab = export_armored(&PgpKey::Secret(b)).unwrap();
    assert_ne!(aa, ab, "S2K salt is randomized, so the two exports must differ somewhere");
    assert_eq!(fpr_from_armor(&aa), fpr_from_armor(&ab), "fingerprint must still match");
}

fn fpr_from_armor(armor: &str) -> String {
    let PgpKey::Secret(sk) = parse_keys(armor.as_bytes()).unwrap().remove(0) else {
        panic!("expected secret key")
    };
    fpr(&sk)
}

// ---------------------------------------------------------------------
// 2. UID / passphrase / expiry don't change the fingerprint
// ---------------------------------------------------------------------

#[test]
fn uid_and_passphrase_do_not_change_key_material() {
    let plain = derive_ed25519(&ROOT_A, &ROOT_ID, 0, "Alice", "alice@example.com", None).unwrap();
    let renamed = derive_ed25519(&ROOT_A, &ROOT_ID, 0, "Completely Different", "other@example.com", None).unwrap();
    let protected = derive_ed25519(&ROOT_A, &ROOT_ID, 0, "Alice", "alice@example.com", Some("pw-123")).unwrap();

    assert_eq!(fpr(&plain), fpr(&renamed), "uid must not affect derivation");
    assert_eq!(fpr(&plain), fpr(&protected), "passphrase must not affect derivation");
    assert_eq!(
        key_info(&PgpKey::Secret(plain)).subkeys[0].key_id,
        key_info(&PgpKey::Secret(protected)).subkeys[0].key_id,
        "encryption subkey must not depend on passphrase"
    );
}

#[test]
fn derived_key_supports_edit_operations() {
    // The recovery story: re-derived keys are normal keys — expiry/uid/
    // passphrase edits all work on them, and none of it moves the
    // fingerprint.
    let key = derive_ed25519(&ROOT_A, &ROOT_ID, 3, "Edit", "edit@example.com", Some("pw")).unwrap();
    let now = 1_800_000_000i64;

    let expired = set_expiration(key.clone(), "pw", Some(365), now).unwrap();
    let info = key_info(&PgpKey::Secret(expired.clone()));
    assert_eq!(info.expires_at, Some(now + 365 * 86_400));

    let added = add_user_id(expired.clone(), "pw", "Second", "second@example.com").unwrap();
    assert_eq!(key_info(&PgpKey::Secret(added.clone())).user_ids.len(), 2);

    assert_eq!(fpr(&added), fpr(&key));
}

// ---------------------------------------------------------------------
// 3. Domain separation
// ---------------------------------------------------------------------

#[test]
fn different_index_or_root_gives_different_keys() {
    let base = derive_ed25519(&ROOT_A, &ROOT_ID, 0, "A", "a@example.com", None).unwrap();
    let idx1 = derive_ed25519(&ROOT_A, &ROOT_ID, 1, "A", "a@example.com", None).unwrap();
    let root_b = derive_ed25519(&ROOT_B, &ROOT_ID, 0, "A", "a@example.com", None).unwrap();
    assert_ne!(fpr(&base), fpr(&idx1));
    assert_ne!(fpr(&base), fpr(&root_b));
    assert_ne!(fpr(&idx1), fpr(&root_b));
}

#[test]
fn derive_p521_is_deterministic_and_domain_separated() {
    let a = derive_p521(&[7u8; 32], &ROOT_ID, 3, "P", "p@example.com", None).unwrap();
    let b = derive_p521(&[7u8; 32], &ROOT_ID, 3, "Q", "q@example.com", Some("pw")).unwrap();
    assert_eq!(fpr(&a), fpr(&b), "uid/passphrase must not change the key");

    let c = derive_p521(&[7u8; 32], &ROOT_ID, 4, "P", "p@example.com", None).unwrap();
    let d = derive_p521(&[8u8; 32], &ROOT_ID, 3, "P", "p@example.com", None).unwrap();
    assert_ne!(fpr(&a), fpr(&c), "different index must diverge");
    assert_ne!(fpr(&a), fpr(&d), "different root must diverge");

    // The P-521 stream is independent of the Ed25519 one: same root, same
    // index, different algorithm => different key.
    let e = derive_ed25519(&[7u8; 32], &ROOT_ID, 3, "P", "p@example.com", None).unwrap();
    assert_ne!(fpr(&a), fpr(&e));
}

// ---------------------------------------------------------------------
// 4. Library-independence proof — the whole point of this unit.
//
// Recompute the derivation from the PLAN-openpgp-keys-import.md §2.3 spec
// using crates OTHER than rpgp's key-generation code (ed25519-dalek,
// x25519-dalek, p521, hkdf/sha2), and confirm the public key material
// embedded in the derived OpenPGP packets matches byte for byte.
// ---------------------------------------------------------------------

const KEY_DERIVATION_SALT: &[u8] = b"com.byteapps.openpgp-keys/key/v1";

fn hkdf_info(prefix: &[u8], index: u32, suffix: &[u8]) -> Vec<u8> {
    let mut info = Vec::new();
    info.extend_from_slice(prefix);
    info.extend_from_slice(&index.to_le_bytes());
    info.extend_from_slice(suffix);
    info
}

fn expand<const N: usize>(root: &[u8; 32], info: &[u8]) -> [u8; N] {
    let hk = Hkdf::<Sha256>::new(Some(KEY_DERIVATION_SALT), root);
    let mut out = [0u8; N];
    hk.expand(info, &mut out).unwrap();
    out
}

fn clamp_x25519(mut k: [u8; 32]) -> [u8; 32] {
    k[0] &= 0b1111_1000;
    k[31] &= 0b0111_1111;
    k[31] |= 0b0100_0000;
    k
}

/// Independent P-521 scalar reduction via `num-bigint`, deliberately not
/// sharing a single line of code with `pgp_core`'s `be_reduce`/`p521_scalar_from_raw`.
fn p521_scalar_via_num_bigint(raw: &[u8; 80]) -> [u8; 66] {
    use num_bigint::BigUint;

    // NIST P-521 group order n (SEC 2 section 2.6.2 / FIPS 186-4 D.1.2.5),
    // written out independently of pgp_core's own copy.
    let n_hex = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa5\
                 1868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409";
    let n = BigUint::parse_bytes(n_hex.as_bytes(), 16).unwrap();
    let one = BigUint::from(1u32);
    let n_minus_1 = &n - &one;

    let x = BigUint::from_bytes_be(raw);
    let scalar = (x % n_minus_1) + one;

    let bytes = scalar.to_bytes_be();
    let mut out = [0u8; 66];
    out[66 - bytes.len()..].copy_from_slice(&bytes);
    out
}

#[test]
fn derive_ed25519_primary_matches_independent_construction() {
    let key = derive_ed25519(&ROOT_A, &ROOT_ID, 2, "Indep", "indep@example.com", None).unwrap();

    let sign_seed: [u8; 32] = expand(&ROOT_A, &hkdf_info(b"ed25519/", 2, b"/sign"));
    let independent = ed25519_dalek::SigningKey::from_bytes(&sign_seed);
    let independent_pub = independent.verifying_key().to_bytes();

    match public_params(&key) {
        PublicParams::EdDSALegacy(EddsaLegacyPublicParams::Ed25519 { key }) => {
            assert_eq!(key.to_bytes(), independent_pub);
        }
        other => panic!("expected EdDSALegacy/Ed25519 public params, got {other:?}"),
    }
}

#[test]
fn derive_ed25519_subkey_matches_independent_construction() {
    let key = derive_ed25519(&ROOT_A, &ROOT_ID, 2, "Indep", "indep@example.com", None).unwrap();

    let enc_key: [u8; 32] = expand(&ROOT_A, &hkdf_info(b"ed25519/", 2, b"/encrypt"));
    let clamped = clamp_x25519(enc_key);
    let independent_secret = x25519_dalek::StaticSecret::from(clamped);
    let independent_pub = x25519_dalek::PublicKey::from(&independent_secret);

    match subkey_public_params(&key) {
        PublicParams::ECDH(EcdhPublicParams::Curve25519Legacy { p, .. }) => {
            assert_eq!(p.to_bytes(), independent_pub.to_bytes());
        }
        other => panic!("expected ECDH/Curve25519Legacy public params, got {other:?}"),
    }
}

#[test]
fn derive_p521_primary_matches_independent_construction() {
    let key = derive_p521(&ROOT_A, &ROOT_ID, 2, "Indep", "indep@example.com", None).unwrap();

    let sign_raw: [u8; 80] = expand(&ROOT_A, &hkdf_info(b"p521/", 2, b"/sign"));
    let scalar = p521_scalar_via_num_bigint(&sign_raw);
    let independent_secret = p521::SecretKey::from_slice(&scalar).unwrap();
    let independent_pub = independent_secret.public_key();

    match public_params(&key) {
        PublicParams::ECDSA(EcdsaPublicParams::P521 { key }) => {
            assert_eq!(*key, independent_pub);
        }
        other => panic!("expected ECDSA/P521 public params, got {other:?}"),
    }
}

#[test]
fn derive_p521_subkey_matches_independent_construction() {
    let key = derive_p521(&ROOT_A, &ROOT_ID, 2, "Indep", "indep@example.com", None).unwrap();

    let enc_raw: [u8; 80] = expand(&ROOT_A, &hkdf_info(b"p521/", 2, b"/encrypt"));
    let scalar = p521_scalar_via_num_bigint(&enc_raw);
    let independent_secret = p521::SecretKey::from_slice(&scalar).unwrap();
    let independent_pub = independent_secret.public_key();

    match subkey_public_params(&key) {
        PublicParams::ECDH(EcdhPublicParams::P521 { p, .. }) => {
            assert_eq!(*p, independent_pub);
        }
        other => panic!("expected ECDH/P521 public params, got {other:?}"),
    }
}

// ---------------------------------------------------------------------
// 5. Pinned fingerprints — FROZEN. Computed once against rpgp 0.20.0;
// any future bump that moves these means re-derivation from the same
// imported words no longer reproduces a user's existing identity.
// ---------------------------------------------------------------------

#[test]
fn ed25519_fingerprints_are_pinned() {
    let idx0 = fpr(&derive_ed25519(&ROOT_A, &ROOT_ID, 0, "Pin", "pin@example.com", None).unwrap());
    let idx1 = fpr(&derive_ed25519(&ROOT_A, &ROOT_ID, 1, "Pin", "pin@example.com", None).unwrap());
    assert_eq!(idx0, "050CC9E9FE9DAF04779E6E3460CF3D7627B974A8");
    assert_eq!(idx1, "D3B630FA7F87033F7735599D4DC6D156C2C157DB");
}

#[test]
fn p521_fingerprints_are_pinned() {
    let idx0 = fpr(&derive_p521(&ROOT_A, &ROOT_ID, 0, "Pin", "pin@example.com", None).unwrap());
    let idx1 = fpr(&derive_p521(&ROOT_A, &ROOT_ID, 1, "Pin", "pin@example.com", None).unwrap());
    assert_eq!(idx0, "B142250EDEB58834DD396FE46AF6CD71E92A8F5C");
    assert_eq!(idx1, "2CB09C8C7989E6160DDDD5294734BBBA44B6CE4F");
}

// ---------------------------------------------------------------------
// 6. Round-trip
// ---------------------------------------------------------------------

#[test]
fn derived_key_roundtrips_and_passphrase_works() {
    let key = derive_ed25519(&ROOT_A, &ROOT_ID, 7, "Roundtrip", "rt@example.com", Some("derive-pw")).unwrap();
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
fn derive_p521_roundtrips_and_passphrase_works() {
    let key = derive_p521(&[9u8; 32], &ROOT_ID, 0, "P", "p@example.com", Some("d-pass")).unwrap();
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
    for (name, key) in [
        ("ed25519", derive_ed25519(&[3u8; 32], &ROOT_ID, 0, "D", "d@example.com", Some("pw")).unwrap()),
        ("p521", derive_p521(&[3u8; 32], &ROOT_ID, 0, "D", "d@example.com", Some("pw")).unwrap()),
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

// ---------------------------------------------------------------------
// 7. ECDH KDF params (part of the subkey fingerprint — normative, per
// PLAN-openpgp-keys-import.md §2.3).
// ---------------------------------------------------------------------

#[test]
fn derive_ed25519_ecdh_kdf_params_are_sha256_aes128() {
    let key = derive_ed25519(&ROOT_A, &ROOT_ID, 0, "K", "k@example.com", None).unwrap();
    match subkey_public_params(&key) {
        PublicParams::ECDH(EcdhPublicParams::Curve25519Legacy { hash, alg_sym, .. }) => {
            assert_eq!(*hash, pgp::crypto::hash::HashAlgorithm::Sha256);
            assert_eq!(*alg_sym, pgp::crypto::sym::SymmetricKeyAlgorithm::AES128);
        }
        other => panic!("expected ECDH/Curve25519Legacy, got {other:?}"),
    }
}

#[test]
fn derive_p521_ecdh_kdf_params_are_sha512_aes256() {
    let key = derive_p521(&ROOT_A, &ROOT_ID, 0, "K", "k@example.com", None).unwrap();
    match subkey_public_params(&key) {
        PublicParams::ECDH(EcdhPublicParams::P521 { hash, alg_sym, .. }) => {
            assert_eq!(*hash, pgp::crypto::hash::HashAlgorithm::Sha512);
            assert_eq!(*alg_sym, pgp::crypto::sym::SymmetricKeyAlgorithm::AES256);
        }
        other => panic!("expected ECDH/P521, got {other:?}"),
    }
}

// ---------------------------------------------------------------------
// 8. Provenance notation (PLAN-openpgp-keys-import.md §6). A derived key's
// primary self-certification carries a `derived@byteapps.com` notation
// recording the root/index/algorithm that produced it, so any importer can
// tell where the key came from without guesswork. The fingerprint is
// unaffected — the notation lives in a signature packet, never the public
// key packet.
// ---------------------------------------------------------------------

fn user_cert(key: &pgp::composed::SignedSecretKey, uid_index: usize) -> &pgp::packet::Signature {
    key.details.users[uid_index]
        .signatures
        .first()
        .expect("user ID must carry a self-signature")
}

#[test]
fn derived_ed25519_carries_provenance_notation() {
    let key = derive_ed25519(&ROOT_A, &ROOT_ID, 7, "Prov", "prov@example.com", None).unwrap();

    let got = provenance(&PgpKey::Secret(key.clone())).expect("expected provenance");
    assert_eq!(
        got,
        Provenance {
            version: 1,
            root_id: ROOT_ID,
            index: 7,
            alg: DerivedAlg::Ed25519,
        }
    );

    // The raw notation value string is exactly the spec's format.
    let notation = user_cert(&key, 0)
        .notations()
        .into_iter()
        .find(|n| n.name.as_ref() == b"derived@byteapps.com")
        .expect("notation must be present");
    assert_eq!(
        std::str::from_utf8(notation.value.as_ref()).unwrap(),
        "v1;root=AABBCCDD;idx=7;alg=ed25519"
    );
    assert!(notation.readable, "notation must be human-readable");
}

#[test]
fn derived_p521_carries_provenance_notation() {
    let key = derive_p521(&ROOT_A, &ROOT_ID, 3, "Prov", "prov@example.com", None).unwrap();

    let got = provenance(&PgpKey::Secret(key.clone())).expect("expected provenance");
    assert_eq!(
        got,
        Provenance {
            version: 1,
            root_id: ROOT_ID,
            index: 3,
            alg: DerivedAlg::P521,
        }
    );

    let notation = user_cert(&key, 0)
        .notations()
        .into_iter()
        .find(|n| n.name.as_ref() == b"derived@byteapps.com")
        .expect("notation must be present");
    assert_eq!(
        std::str::from_utf8(notation.value.as_ref()).unwrap(),
        "v1;root=AABBCCDD;idx=3;alg=p521"
    );
}

#[test]
fn random_keys_have_no_provenance() {
    let ed = generate_ed25519("Random", "random@example.com", None).unwrap();
    assert_eq!(provenance(&PgpKey::Secret(ed)), None);

    let p256 = generate_nistp(NistCurve::P256, "Random", "random@example.com", None).unwrap();
    assert_eq!(provenance(&PgpKey::Secret(p256)), None);

    let rsa = generate_rsa(2048, "Random", "random@example.com", None).unwrap();
    assert_eq!(provenance(&PgpKey::Secret(rsa)), None);
}

#[test]
fn provenance_survives_set_expiration() {
    let key = derive_ed25519(&ROOT_A, &ROOT_ID, 1, "Exp", "exp@example.com", Some("pw")).unwrap();
    let before = provenance(&PgpKey::Secret(key.clone())).expect("expected provenance");

    let expired = set_expiration(key, "pw", Some(365), 1_800_000_000).unwrap();
    let after = provenance(&PgpKey::Secret(expired)).expect("provenance must survive set_expiration");
    assert_eq!(before, after);
}

#[test]
fn provenance_survives_add_user_id_on_both_uids() {
    let key = derive_ed25519(&ROOT_A, &ROOT_ID, 2, "Uid", "uid@example.com", Some("pw")).unwrap();
    let added = add_user_id(key, "pw", "Second", "second@example.com").unwrap();

    assert_eq!(added.details.users.len(), 2);
    // Both the original and the newly added user ID's self-certs must carry
    // the notation — a desktop app importing either UID's cert should be
    // able to recover provenance.
    let cert0 = provenance_from_signature_via_key_info(&added, 0);
    let cert1 = provenance_from_signature_via_key_info(&added, 1);
    assert_eq!(cert0, cert1);
    assert!(cert0.is_some());
}

/// `provenance()` only looks at the LATEST self-cert across all user IDs, so
/// to check a specific user ID's own certification we read its notation
/// directly rather than through the public `provenance()` entry point.
fn provenance_from_signature_via_key_info(
    key: &pgp::composed::SignedSecretKey,
    uid_index: usize,
) -> Option<Provenance> {
    let sig = user_cert(key, uid_index);
    let notation = sig
        .notations()
        .into_iter()
        .find(|n| n.name.as_ref() == b"derived@byteapps.com")?;
    let value = std::str::from_utf8(notation.value.as_ref()).ok()?;
    // Reuses the same value format the crate emits; parsed by hand here
    // since `parse_provenance_value` is a private helper.
    let mut parts = value.split(';');
    if parts.next()? != "v1" {
        return None;
    }
    let root = parts.next()?.strip_prefix("root=")?;
    let idx = parts.next()?.strip_prefix("idx=")?.parse().ok()?;
    let alg = match parts.next()?.strip_prefix("alg=")? {
        "ed25519" => DerivedAlg::Ed25519,
        "p521" => DerivedAlg::P521,
        _ => return None,
    };
    let mut root_id = [0u8; 4];
    for (i, b) in root_id.iter_mut().enumerate() {
        *b = u8::from_str_radix(&root[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(Provenance { version: 1, root_id, index: idx, alg })
}

#[test]
fn provenance_survives_change_passphrase() {
    let key = derive_p521(&ROOT_A, &ROOT_ID, 9, "Chg", "chg@example.com", Some("old")).unwrap();
    let before = provenance(&PgpKey::Secret(key.clone())).expect("expected provenance");

    let changed = change_passphrase(key, "old", Some("new")).unwrap();
    let after = provenance(&PgpKey::Secret(changed)).expect("provenance must survive change_passphrase");
    assert_eq!(before, after);
}

#[test]
fn provenance_survives_export_and_reparse() {
    let key = derive_ed25519(&ROOT_A, &ROOT_ID, 42, "Exp", "exp2@example.com", None).unwrap();
    let before = provenance(&PgpKey::Secret(key.clone())).expect("expected provenance");

    let armored = export_armored(&PgpKey::Secret(key)).unwrap();
    let reparsed = parse_keys(armored.as_bytes()).unwrap().remove(0);
    let after = provenance(&reparsed).expect("provenance must survive export/reparse");
    assert_eq!(before, after);
}

/// Malformed notation values must never panic and must return `None`, not a
/// best-effort guess.
#[test]
fn malformed_provenance_values_are_rejected() {
    let bad_values = [
        "v2;root=AABBCCDD;idx=7;alg=ed25519",      // wrong version
        "v1;root=ZZZZZZZZ;idx=7;alg=ed25519",      // non-hex root
        "v1;root=AABBCCDD;idx=7",                  // missing alg
        "v1;root=AABBCCDD;idx=7;alg=rot13",        // unknown alg
        "v1;root=AABBC;idx=7;alg=ed25519",         // short root
        "v1;root=AABBCCDD;idx=notanumber;alg=ed25519", // bad index
        "not-even-close-to-the-format",
        "",
    ];
    for value in bad_values {
        let key = derive_ed25519(&ROOT_A, &ROOT_ID, 0, "Bad", "bad@example.com", None).unwrap();
        let mutated = resign_with_raw_notation_value(&key, value);
        assert_eq!(
            provenance(&PgpKey::Secret(mutated)),
            None,
            "expected None for malformed value {value:?}"
        );
    }
}

/// Build a fresh, later-dated self-certification carrying an arbitrary
/// (possibly malformed) notation value, using nothing but rpgp's public
/// signing API — the same primitives `pgp_core`'s own signing helpers use
/// internally. Lets the malformed-value test above exercise `provenance()`
/// against untrusted notation content without needing to reach into
/// `pgp_core`'s private signing functions.
fn resign_with_raw_notation_value(
    key: &pgp::composed::SignedSecretKey,
    value: &str,
) -> pgp::composed::SignedSecretKey {
    use pgp::packet::{
        Features, KeyFlags, Notation, PacketTrait, SignatureConfig, SignatureType, Subpacket,
        SubpacketData,
    };
    use pgp::types::{KeyDetails as _, Password, Timestamp};
    use rand::thread_rng;

    let primary = &key.primary_key;
    let uid = &key.details.users[0].id;

    let mut rng = thread_rng();
    let mut config =
        SignatureConfig::from_key(&mut rng, primary, SignatureType::CertPositive).unwrap();

    let mut keyflags = KeyFlags::default();
    keyflags.set_certify(true);
    keyflags.set_sign(true);
    let mut features = Features::default();
    features.set_seipd_v1(true);

    config.hashed_subpackets = vec![
        // Later than DERIVED_KEY_CREATED_AT, so `latest_self_cert` picks
        // THIS signature over the one `derive_ed25519` produced.
        Subpacket::regular(SubpacketData::SignatureCreationTime(Timestamp::from_secs(
            DERIVED_KEY_CREATED_AT + 1,
        )))
        .unwrap(),
        Subpacket::regular(SubpacketData::IssuerFingerprint(primary.fingerprint())).unwrap(),
        Subpacket::regular(SubpacketData::KeyFlags(keyflags)).unwrap(),
        Subpacket::regular(SubpacketData::Features(features)).unwrap(),
        Subpacket::regular(SubpacketData::IsPrimary(true)).unwrap(),
        Subpacket::regular(SubpacketData::Notation(Notation {
            readable: true,
            name: "derived@byteapps.com".into(),
            value: value.to_string().into(),
        }))
        .unwrap(),
    ];
    config.unhashed_subpackets = vec![Subpacket::regular(SubpacketData::IssuerKeyId(
        primary.legacy_key_id(),
    ))
    .unwrap()];

    let pw = Password::empty();
    let sig = config
        .sign_certification(primary, primary.public_key(), &pw, uid.tag(), uid)
        .unwrap();

    let mut k = key.clone();
    k.details.users[0].signatures.push(sig);
    k
}
