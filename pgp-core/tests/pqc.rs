//! RFC 9980 post-quantum prototype checks (rpgp `draft-pqc` feature).
//!
//! The one PQC shape that stays a v4 key — and therefore coexists with the
//! rest of this app's v4 world — is an ML-KEM-768+X25519 ENCRYPTION subkey
//! (RFC 9980 allows algorithm 35 on v4 keys; the ML-DSA/SLH-DSA signature
//! algorithms are v6-only and out of scope here). GnuPG 2.2 knows nothing
//! about algorithm 35, so there is deliberately NO gpg interop here — just
//! rpgp-side generation, armor round-trip, and encrypt/decrypt.

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
