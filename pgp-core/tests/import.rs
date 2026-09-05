//! Imported-seed root derivation — PLAN-openpgp-keys-import.md §2.1–2.2,
//! §2.4. Pinned vectors here (computed once with `pgp-core`'s own code and
//! cross-checked below) are the cross-platform contract: a future
//! desktop/mobile OpenPGP Keys app must reproduce the SAME `seed64`,
//! `root`, `root_id`, and `xfp` from the same words + passphrase.
//!
//! MUTATION CHECK (run manually, not committed): flipping one byte of
//! `ROOT_SALT` in `pgp-core/src/import.rs` and re-running
//! `pinned_root_*` below must turn them red. Confirmed 2026-09-04, salt
//! restored afterward — see this unit's report for the exact diff/output.

use pgp_core::import::{
    bip39, derive_root, mnemonic_to_seed64, normalize_mnemonic, normalize_passphrase,
    seedqr_to_mnemonic,
};
use sha2::{Digest, Sha256};

const TREZOR_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
     abandon abandon abandon about";

// The reference-signer simulator's fixed 24-word test seed (plan §2.4 /
// §7). No vendor name appears here or anywhere else in this file (memory
// `no-vendor-names-public-repos`) — it is just "the reference-signer
// vector" in comments.
const REF_MNEMONIC: &str = "wife shiver author away frog air rough vanish fantasy frozen noodle \
     athlete pioneer citizen symptom firm much faith extend rare axis garment kiwi clarify";

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

// ---------------------------------------------------------------------
// BIP-39 spec vector + wordlist pin
// ---------------------------------------------------------------------

#[test]
fn bip39_spec_vector_seed64() {
    let m = normalize_mnemonic(TREZOR_MNEMONIC).unwrap();
    let p = normalize_passphrase("TREZOR").unwrap();
    let seed64 = mnemonic_to_seed64(&m, &p);
    assert_eq!(
        hex(seed64.as_ref()),
        "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d1826\
         4c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
    );
}

/// Cross-check against an independent BIP-39 implementation (the
/// `bip39` crate, dev-dependency-only, never used by the derivation
/// itself) over several 12- and 24-word mnemonics generated from fixed
/// entropy patterns — the "two more vectors" the plan asks for, without
/// hand-transcribing official test-vector hex from memory.
#[test]
fn bip39_crate_cross_check() {
    let cases: &[(&[u8], &str)] = &[
        (&[0u8; 16], ""),
        (&[0xffu8; 16], "hunter2"),
        (&[0u8; 32], "TREZOR"),
        (&[0xffu8; 32], ""),
        (
            &[
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                0x0e, 0x0f, 0x10,
            ],
            "correct horse",
        ),
        (
            &[
                0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xaa, 0xbb, 0xcc,
                0xdd, 0xee, 0xff, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x10, 0x32,
                0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
            ],
            "",
        ),
    ];

    for (entropy, passphrase) in cases {
        let mnemonic = bip39::entropy_to_mnemonic(entropy).unwrap();
        assert!(matches!(mnemonic.split(' ').count(), 12 | 24));

        // The external crate agrees the mnemonic is well-formed...
        let ext = ::bip39::Mnemonic::parse_in_normalized(::bip39::Language::English, &mnemonic)
            .expect("our generated mnemonic must be valid BIP-39");
        // ...and produces byte-identical PBKDF2 seed material.
        let ours = mnemonic_to_seed64(&mnemonic, passphrase);
        let theirs = ext.to_seed(*passphrase);
        assert_eq!(ours.as_slice(), &theirs[..], "seed64 mismatch for entropy {}", hex(entropy));

        // Round-trips back to the same entropy through our own decoder.
        assert_eq!(bip39::mnemonic_to_entropy(&mnemonic).unwrap(), *entropy);
    }
}

#[test]
fn wordlist_sha256_pin() {
    let bytes = include_bytes!("../src/import/english.txt");
    let got = hex(&Sha256::digest(bytes));
    assert_eq!(got, "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda");
}

// ---------------------------------------------------------------------
// Rejections
// ---------------------------------------------------------------------

#[test]
fn reject_wrong_word_counts() {
    for n in [15usize, 18, 21] {
        let words = bip39::wordlist();
        let mnemonic = vec![words[0]; n].join(" ");
        let err = normalize_mnemonic(&mnemonic).unwrap_err();
        assert_eq!(err.0, "Enter 12 or 24 words", "word count {n}");
    }
}

#[test]
fn reject_unknown_word() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon \
         abandon abandon abandon notaword";
    let err = normalize_mnemonic(mnemonic).unwrap_err();
    assert_eq!(err.0, "Unknown word: notaword");
}

#[test]
fn reject_bad_checksum() {
    // Swap two words of a valid 12-word mnemonic (both still in the
    // wordlist) so the checksum no longer validates.
    let bad = "about abandon abandon abandon abandon abandon abandon abandon \
         abandon abandon abandon abandon";
    let err = normalize_mnemonic(bad).unwrap_err();
    assert_eq!(err.0, "Checksum does not match — check the words");
}

#[test]
fn reject_long_passphrase() {
    let ok = "a".repeat(100);
    normalize_passphrase(&ok).expect("100 chars is fine");

    let too_long = "a".repeat(101);
    let err = normalize_passphrase(&too_long).unwrap_err();
    assert_eq!(err.0, "Passphrase must be 100 characters or fewer");
}

// ---------------------------------------------------------------------
// Normalization
// ---------------------------------------------------------------------

#[test]
fn normalize_whitespace_and_case() {
    let messy = "  Abandon   ABANDON  abandon abandon abandon abandon abandon abandon \
         abandon abandon abandon  About ";
    let clean = normalize_mnemonic(messy).unwrap();
    assert_eq!(
        clean.as_str(),
        "abandon abandon abandon abandon abandon abandon abandon abandon \
         abandon abandon abandon about"
    );
}

#[test]
fn normalize_24_word_double_spaces_parses() {
    let doubled = REF_MNEMONIC.replace(' ', "  ");
    let clean = normalize_mnemonic(&doubled).unwrap();
    assert_eq!(clean.split(' ').count(), 24);
    assert_eq!(clean.as_str(), REF_MNEMONIC);
}

#[test]
fn normalize_passphrase_nfkd_composed_vs_decomposed_same_root() {
    let composed = "caf\u{00e9}"; // "café", precomposed é (U+00E9)
    let decomposed = "cafe\u{0301}"; // "café", e + combining acute (U+0065 U+0301)
    assert_ne!(composed, decomposed, "test fixture sanity: byte-different inputs");

    let a = derive_root(REF_MNEMONIC, composed).unwrap();
    let b = derive_root(REF_MNEMONIC, decomposed).unwrap();
    assert_eq!(a.root.as_slice(), b.root.as_slice());
    assert_eq!(a.root_id, b.root_id);
    assert_eq!(a.xfp, b.xfp);
}

// ---------------------------------------------------------------------
// Pinned roots (§2.4) — FROZEN. Computed once with this unit's own code;
// re-derive independently (or via the reference-signer cross-check, U5)
// before ever changing them.
// ---------------------------------------------------------------------

#[test]
fn pinned_root_trezor_vector() {
    let r = derive_root(TREZOR_MNEMONIC, "TREZOR").unwrap();
    assert_eq!(r.words, 12);
    assert!(r.pass_used);
    assert_eq!(
        hex(r.root.as_ref()),
        "08225019b0efa5be9d1a6c6f63d3a7628f3dd8903e7c04b94c2a50af8f039b6a"
    );
    assert_eq!(hex(&r.root_id), "5f6be3a4");
    assert_eq!(hex(&r.xfp), "b4e3f5ed");
    assert_eq!(r.root_id_hex(), "5F6BE3A4");
    assert_eq!(r.xfp_hex(), "b4e3f5ed");
}

#[test]
fn pinned_root_reference_signer_empty_passphrase() {
    let r = derive_root(REF_MNEMONIC, "").unwrap();
    assert_eq!(r.words, 24);
    assert!(!r.pass_used);
    assert_eq!(
        hex(r.root.as_ref()),
        "3b895bc5d7f7191e8d4b4d6c6f496b916dc42c4526003994a9cf2415a8a2369e"
    );
    assert_eq!(hex(&r.root_id), "c903539b");
    assert_eq!(hex(&r.xfp), "0f056943");
}

#[test]
fn pinned_root_reference_signer_test_passphrase() {
    let r = derive_root(REF_MNEMONIC, "test").unwrap();
    assert_eq!(r.words, 24);
    assert!(r.pass_used);
    assert_eq!(
        hex(r.root.as_ref()),
        "012947874b10e992914e951f00aec9f25f9206b868bcaf53d82a6c5c78213e51"
    );
    assert_eq!(hex(&r.root_id), "af28d2f7");
    assert_eq!(hex(&r.xfp), "86ff505a");
}

#[test]
fn pinned_roots_differ_by_passphrase() {
    let a = derive_root(REF_MNEMONIC, "").unwrap();
    let b = derive_root(REF_MNEMONIC, "test").unwrap();
    assert_ne!(a.root.as_slice(), b.root.as_slice());
    assert_ne!(a.root_id, b.root_id);
    assert_ne!(a.xfp, b.xfp);
}

// ---------------------------------------------------------------------
// SeedQR decoding (standard + CompactSeedQR)
// ---------------------------------------------------------------------

#[test]
fn seedqr_standard_12word_all_abandon_about() {
    // "abandon" x11 (index 0) + "about" (index 3): 11 groups of "0000"
    // plus one "0003" = 44 zeros followed by "0003", 48 digits total.
    let digits = "0000".repeat(11) + "0003";
    assert_eq!(digits.len(), 48);
    let mnemonic = seedqr_to_mnemonic(digits.as_bytes()).unwrap();
    assert_eq!(mnemonic, TREZOR_MNEMONIC);
    // And it's a valid, checksum-correct mnemonic on its own.
    normalize_mnemonic(&mnemonic).unwrap();
}

#[test]
fn seedqr_standard_24word_round_trips_through_indices() {
    // Build a standard-SeedQR digit string from REF_MNEMONIC's own word
    // indices, then decode it back and check we recover the same words.
    let list = bip39::wordlist();
    let words: Vec<&str> = REF_MNEMONIC.split(' ').collect();
    assert_eq!(words.len(), 24);
    let digits: String = words
        .iter()
        .map(|w| {
            let idx = list.binary_search(w).unwrap();
            format!("{idx:04}")
        })
        .collect();
    assert_eq!(digits.len(), 96);

    let mnemonic = seedqr_to_mnemonic(digits.as_bytes()).unwrap();
    assert_eq!(mnemonic, REF_MNEMONIC);
}

#[test]
fn seedqr_compact_12_and_24_byte_forms() {
    for entropy in [&[0u8; 16][..], &[0u8; 32][..], &[0xffu8; 16][..], &[0xffu8; 32][..]] {
        let want = bip39::entropy_to_mnemonic(entropy).unwrap();
        let got = seedqr_to_mnemonic(entropy).unwrap();
        assert_eq!(got, want);
    }
}

#[test]
fn seedqr_rejects_wrong_shapes() {
    // Wrong length entirely.
    assert_eq!(seedqr_to_mnemonic(&[0u8; 10]).unwrap_err().0, "Not a SeedQR");
    // Right length for standard form, but not all ASCII digits.
    let mut not_digits = [b'0'; 48];
    not_digits[0] = b'x';
    assert_eq!(seedqr_to_mnemonic(&not_digits).unwrap_err().0, "Not a SeedQR");
    // Right length for standard form, all digits, but an out-of-range index
    // (2048 does not name a wordlist entry).
    let oob = "0000".repeat(11) + "2048";
    assert_eq!(oob.len(), 48);
    assert_eq!(seedqr_to_mnemonic(oob.as_bytes()).unwrap_err().0, "Not a SeedQR");
}

/// Sanity check for the fixed-width hex helpers used above/in the app —
/// exercises `unhex` so it isn't flagged as dead code and doubles as a
/// belt-and-braces check that `hex`/`unhex` round-trip.
#[test]
fn hex_helpers_round_trip() {
    let bytes = [0xde, 0xad, 0xbe, 0xef];
    assert_eq!(unhex(&hex(&bytes)), bytes);
}

// ---------------------------------------------------------------------
// Reference-signer parity (plan §7) — proves our seed64/xfp match the
// hardware signer's own firmware for the same words + passphrase. The
// fixture is generated by the private driving script; no vendor name
// appears here (memory `no-vendor-names-public-repos`).
// ---------------------------------------------------------------------

#[test]
fn reference_signer_fixture_matches() {
    let raw = include_str!("fixtures/reference-signer-seeds.json");
    let entries: serde_json::Value = serde_json::from_str(raw).expect("valid JSON fixture");
    let entries = entries.as_array().expect("fixture is a JSON array");
    assert!(!entries.is_empty(), "fixture must not be empty");

    for entry in entries {
        let name = entry["name"].as_str().expect("entry.name");
        let words = entry["words"].as_str().expect("entry.words");
        let passphrase = entry["passphrase"].as_str().expect("entry.passphrase");
        let seed64_hex = entry["seed64_hex"].as_str().expect("entry.seed64_hex");
        let xfp_hex = entry["xfp_hex"].as_str().expect("entry.xfp_hex");

        let m = normalize_mnemonic(words).unwrap_or_else(|e| panic!("{name}: {e}"));
        let p = normalize_passphrase(passphrase).unwrap_or_else(|e| panic!("{name}: {e}"));
        let seed64 = mnemonic_to_seed64(&m, &p);
        assert_eq!(hex(seed64.as_ref()), seed64_hex, "seed64 mismatch for {name}");

        let root = derive_root(words, passphrase).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(hex(&root.xfp), xfp_hex, "xfp mismatch for {name}");
    }
}

// ---------------------------------------------------------------------
// suggest()
// ---------------------------------------------------------------------

#[test]
fn suggest_full_prefix_returns_single_word() {
    assert_eq!(bip39::suggest("aban", 10), vec!["abandon"]);
}

#[test]
fn suggest_short_prefix_returns_max_entries() {
    let got = bip39::suggest("ab", 3);
    assert_eq!(got.len(), 3);
    assert!(got.iter().all(|w| w.starts_with("ab")));
}

/// End-to-end golden vector, pinned from an independent run of the whole
/// pipeline on the device build (hosted simulator, 2026-09-04): the BIP-39
/// spec phrase with NO passphrase → root → Ed25519 key #0. The root id and
/// the master fingerprint were cross-checked against a from-scratch Python
/// HKDF/BIP-32 computation; the OpenPGP fingerprint is what the app logged.
/// A future desktop/mobile OpenPGP Keys build must reproduce all three.
#[test]
fn golden_spec_phrase_no_passphrase_to_ed25519_key_0() {
    let r = pgp_core::import::derive_root(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "",
    )
    .unwrap();
    assert_eq!(r.root_id_hex(), "E6C8985D");
    assert_eq!(r.xfp_hex(), "73c5da0a");
    let key = pgp_core::derive_ed25519(&r.root, &r.root_id, 0, "Seed Test", "seed-test@example.com", None)
        .unwrap();
    let info = pgp_core::key_info(&pgp_core::PgpKey::Secret(key));
    assert_eq!(info.fingerprint, "D3BD8DFD5394E96799AB797F3D32DE84718941B9");
    let p = info.provenance.expect("derived key carries provenance");
    assert_eq!((p.root_id, p.index), (r.root_id, 0));
}
