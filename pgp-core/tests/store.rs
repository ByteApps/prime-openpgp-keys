//! Tests for `pgp_core::store` — sealing/opening the imported-seed root at
//! rest (PLAN-openpgp-keys-import.md §4, U3).

use hkdf::Hkdf;
use sha2::Sha256;

use pgp_core::store::{self, RootMeta, BLOB_LEN};

const APP_SEED: [u8; 32] = [0x42; 32];
const META: RootMeta = RootMeta {
    words: 24,
    pass_used: true,
    root_id: [0xAA, 0xBB, 0xCC, 0xDD],
};
const ROOT: [u8; 32] = [0x11; 32];
const XFP: [u8; 4] = [0x0F, 0x05, 0x69, 0x43];
const FIXED_NONCE: [u8; 24] = [0x07; 24];

/// FROZEN format contract — computed once (see the U3 report), pasted here.
/// If this test ever needs to change, the on-disk format has changed and
/// every already-sealed `/.imported_key` file on a device breaks.
const PINNED_BLOB_HEX: &str = "4f50474b011801aabbccdd070707070707070707070707070707070707070707070707978066b3b5dabe357cc9ef41c11e88cdc1533d84ae8b3c64e83644df3e1cb252be86c62a2cf24a1c2ca9fce098a13fbcef2fdbe8";

/// The sealing key HKDF derives for `APP_SEED = [0x42; 32]`, independently
/// recomputed here straight from `hkdf`/`sha2` (not through `store`'s
/// internals) so this test also pins the `STORE_SALT`/`STORE_INFO` strings.
const PINNED_SEALING_KEY_HEX: &str =
    "f1d2309928832562e703ae88124df9241012b4bc864f3e8e59f3e99730d8f996";

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// ---------------------------------------------------------------------
// Round-trip
// ---------------------------------------------------------------------

#[test]
fn round_trip_seal_then_open() {
    let blob = store::seal_root(&APP_SEED, &META, &ROOT, &XFP).unwrap();
    assert_eq!(blob.len(), BLOB_LEN);

    let peeked = store::peek_meta(&blob).unwrap();
    assert_eq!(peeked.words, META.words);
    assert_eq!(peeked.pass_used, META.pass_used);
    assert_eq!(peeked.root_id, META.root_id);

    let (meta, unsealed) = store::open_root(&APP_SEED, &blob).unwrap();
    assert_eq!(meta.words, META.words);
    assert_eq!(meta.pass_used, META.pass_used);
    assert_eq!(meta.root_id, META.root_id);
    assert_eq!(*unsealed.root, ROOT);
    assert_eq!(*unsealed.xfp, XFP);
}

#[test]
fn peek_meta_matches_open_root_without_the_key() {
    let blob = store::seal_root(&APP_SEED, &META, &ROOT, &XFP).unwrap();
    let peeked = store::peek_meta(&blob).unwrap();
    let (opened, _) = store::open_root(&APP_SEED, &blob).unwrap();
    assert_eq!(peeked, opened);
}

#[test]
fn xfp_bytes_never_appear_in_cleartext_in_the_blob() {
    let blob = store::seal_root(&APP_SEED, &META, &ROOT, &XFP).unwrap();
    // The only bytes of the blob NOT covered by the AEAD encryption are the
    // 11-byte header (magic/version/words/pass_used/root_id) and the
    // 24-byte nonce; xfp must not show up as a literal run anywhere,
    // ciphertext included (it's encrypted, so this should never fire, but
    // it directly checks the "not in the cleartext header" requirement).
    assert!(
        !blob.windows(XFP.len()).any(|w| w == XFP),
        "xfp bytes leaked into the sealed blob in cleartext"
    );
}

// ---------------------------------------------------------------------
// Nondeterminism / multiple seals
// ---------------------------------------------------------------------

#[test]
fn two_seals_of_the_same_input_differ_and_both_open() {
    let blob_a = store::seal_root(&APP_SEED, &META, &ROOT, &XFP).unwrap();
    let blob_b = store::seal_root(&APP_SEED, &META, &ROOT, &XFP).unwrap();

    assert_ne!(blob_a, blob_b, "two seals produced identical blobs (nonce reuse?)");
    // Headers (first 11 bytes) are pure functions of `meta` and must match;
    // everything from the nonce onward must differ.
    assert_eq!(&blob_a[..11], &blob_b[..11]);
    assert_ne!(&blob_a[11..], &blob_b[11..], "nonce/ciphertext did not change");

    for blob in [&blob_a, &blob_b] {
        let (meta, unsealed) = store::open_root(&APP_SEED, blob).unwrap();
        assert_eq!(meta.root_id, META.root_id);
        assert_eq!(*unsealed.root, ROOT);
        assert_eq!(*unsealed.xfp, XFP);
    }
}

// ---------------------------------------------------------------------
// Wrong key
// ---------------------------------------------------------------------

#[test]
fn wrong_app_seed_gives_the_cannot_unlock_message() {
    let blob = store::seal_root(&APP_SEED, &META, &ROOT, &XFP).unwrap();

    let mut wrong_seed = APP_SEED;
    wrong_seed[0] ^= 0x01; // flip one bit

    let err = store::open_root(&wrong_seed, &blob).unwrap_err();
    assert_eq!(
        err.0,
        "Stored seed cannot be unlocked with this device's seed"
    );
}

// ---------------------------------------------------------------------
// Header tamper (11 bytes: magic..root_id)
// ---------------------------------------------------------------------

#[test]
fn tamper_magic_byte_gives_bad_magic_error() {
    for i in 0..4 {
        let mut blob = store::seal_root(&APP_SEED, &META, &ROOT, &XFP).unwrap();
        blob[i] ^= 0xFF;
        let err = store::peek_meta(&blob).unwrap_err();
        assert!(
            err.0.contains("bad magic"),
            "byte {i}: expected a bad-magic error, got {:?}",
            err.0
        );
        let err = store::open_root(&APP_SEED, &blob).unwrap_err();
        assert!(
            err.0.contains("bad magic"),
            "byte {i}: expected a bad-magic error, got {:?}",
            err.0
        );
    }
}

#[test]
fn tamper_version_byte_gives_unsupported_version_error() {
    let mut blob = store::seal_root(&APP_SEED, &META, &ROOT, &XFP).unwrap();
    blob[4] ^= 0xFF;
    let err = store::peek_meta(&blob).unwrap_err();
    assert!(
        err.0.contains("Unsupported stored-seed format version"),
        "got {:?}",
        err.0
    );
    let err = store::open_root(&APP_SEED, &blob).unwrap_err();
    assert!(
        err.0.contains("Unsupported stored-seed format version"),
        "got {:?}",
        err.0
    );
}

#[test]
fn tamper_words_byte_fails_open() {
    let mut blob = store::seal_root(&APP_SEED, &META, &ROOT, &XFP).unwrap();
    blob[5] ^= 0xFF;
    // Fails either at header validation or at the AEAD step — both are
    // acceptable, the byte must simply never open.
    assert!(store::open_root(&APP_SEED, &blob).is_err());
}

#[test]
fn tamper_pass_used_byte_fails_open() {
    let mut blob = store::seal_root(&APP_SEED, &META, &ROOT, &XFP).unwrap();
    blob[6] ^= 0xFF;
    assert!(store::open_root(&APP_SEED, &blob).is_err());
}

#[test]
fn tamper_each_root_id_byte_fails_open() {
    for i in 7..11 {
        let mut blob = store::seal_root(&APP_SEED, &META, &ROOT, &XFP).unwrap();
        blob[i] ^= 0xFF;
        // root_id has no validation of its own (any 4 bytes are legal), so
        // peek_meta still succeeds — but root_id is part of the AAD, so a
        // changed root_id must fail the AEAD open.
        assert!(store::peek_meta(&blob).is_ok());
        let err = store::open_root(&APP_SEED, &blob).unwrap_err();
        assert_eq!(
            err.0,
            "Stored seed cannot be unlocked with this device's seed",
            "byte {i} tamper did not fail the AEAD open"
        );
    }
}

// ---------------------------------------------------------------------
// Ciphertext / tag tamper
// ---------------------------------------------------------------------

#[test]
fn tamper_ciphertext_byte_fails_open() {
    let mut blob = store::seal_root(&APP_SEED, &META, &ROOT, &XFP).unwrap();
    // header(11) + nonce(24) = 35; ciphertext runs [35..35+36).
    blob[40] ^= 0xFF;
    let err = store::open_root(&APP_SEED, &blob).unwrap_err();
    assert_eq!(
        err.0,
        "Stored seed cannot be unlocked with this device's seed"
    );
}

#[test]
fn tamper_tag_byte_fails_open() {
    let mut blob = store::seal_root(&APP_SEED, &META, &ROOT, &XFP).unwrap();
    // tag is the last 16 bytes: [BLOB_LEN - 16..BLOB_LEN).
    let last = BLOB_LEN - 1;
    blob[last] ^= 0xFF;
    let err = store::open_root(&APP_SEED, &blob).unwrap_err();
    assert_eq!(
        err.0,
        "Stored seed cannot be unlocked with this device's seed"
    );
}

// ---------------------------------------------------------------------
// Length errors
// ---------------------------------------------------------------------

#[test]
fn truncated_blob_fails() {
    let blob = store::seal_root(&APP_SEED, &META, &ROOT, &XFP).unwrap();
    let short = &blob[..blob.len() - 1];
    assert!(store::peek_meta(short).is_err());
    assert!(store::open_root(&APP_SEED, short).is_err());
}

#[test]
fn extended_blob_fails() {
    let blob = store::seal_root(&APP_SEED, &META, &ROOT, &XFP).unwrap();
    let mut long = blob.clone();
    long.push(0x00);
    assert!(store::peek_meta(&long).is_err());
    assert!(store::open_root(&APP_SEED, &long).is_err());
}

// ---------------------------------------------------------------------
// Word count validation
// ---------------------------------------------------------------------

#[test]
fn seal_root_rejects_18_words() {
    let bad_meta = RootMeta {
        words: 18,
        ..META
    };
    let err = store::seal_root(&APP_SEED, &bad_meta, &ROOT, &XFP).unwrap_err();
    assert!(err.0.contains("12 or 24"), "got {:?}", err.0);
}

#[test]
fn seal_root_accepts_12_words() {
    let meta12 = RootMeta {
        words: 12,
        pass_used: false,
        root_id: META.root_id,
    };
    let blob = store::seal_root(&APP_SEED, &meta12, &ROOT, &XFP).unwrap();
    let (meta, unsealed) = store::open_root(&APP_SEED, &blob).unwrap();
    assert_eq!(meta.words, 12);
    assert!(!meta.pass_used);
    assert_eq!(*unsealed.root, ROOT);
}

// ---------------------------------------------------------------------
// Pinned vector (FROZEN format contract)
// ---------------------------------------------------------------------

#[test]
fn pinned_vector_matches_frozen_blob_hex() {
    let blob =
        store::seal_root_with_nonce(&APP_SEED, &META, &ROOT, &XFP, &FIXED_NONCE).unwrap();
    assert_eq!(blob.len(), BLOB_LEN);
    assert_eq!(hex_encode(&blob), PINNED_BLOB_HEX);

    // And it must still open correctly.
    let (meta, unsealed) = store::open_root(&APP_SEED, &blob).unwrap();
    assert_eq!(meta, META);
    assert_eq!(*unsealed.root, ROOT);
    assert_eq!(*unsealed.xfp, XFP);
}

#[test]
fn pinned_vector_matches_frozen_sealing_key_hex() {
    // Independently recomputed straight from hkdf/sha2 (not via any
    // internal store function) so this test also pins the exact
    // HKDF salt/info strings the format contract depends on.
    let prk = Hkdf::<Sha256>::new(
        Some(b"com.byteapps.openpgp-keys/store/v1".as_slice()),
        &APP_SEED,
    );
    let mut key = [0u8; 32];
    prk.expand(b"root-seal", &mut key).unwrap();
    assert_eq!(hex_encode(&key), PINNED_SEALING_KEY_HEX);

    // Sanity: decode the pinned hex constant round-trips too.
    assert_eq!(hex_decode(PINNED_SEALING_KEY_HEX).len(), 32);
    assert_eq!(hex_decode(PINNED_BLOB_HEX).len(), BLOB_LEN);
}
