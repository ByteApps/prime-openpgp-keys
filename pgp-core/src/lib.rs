//! UI-free OpenPGP operations for the PGP Keychain app.
//!
//! Lives in its own crate so it can be unit-tested with plain `cargo test
//! -p pgp-core` on the host — the app crate itself only compiles through the
//! `foundation` CLI (Slint `@ui/` imports).
//!
//! All armor parsing runs behind `catch_unwind`: rpgp has a history of panics
//! on crafted packets (CVE-2026-21895) and imported `.asc` files are
//! untrusted input.

use std::io::Cursor;
use std::panic::{catch_unwind, AssertUnwindSafe};

use pgp::composed::{
    ArmorOptions, DetachedSignature, EncryptionCaps, KeyType, PublicOrSecret,
    SecretKeyParamsBuilder, SubkeyParamsBuilder,
};
use pgp::crypto::ecc_curve::ECCCurve;
use pgp::packet::{
    PacketTrait, Signature, SignatureConfig, SignatureType, Subpacket, SubpacketData, UserId,
};
use pgp::ser::Serialize as _;
use pgp::types::{
    Duration as PgpDuration, Fingerprint, KeyDetails as _, KeyVersion, Password, PublicParams,
    SignedUser, SigningKey, Timestamp,
};
use rand::thread_rng;
use rsa::traits::PublicKeyParts;

// Re-exported so the app crate doesn't need its own `pgp` dependency.
pub use pgp::composed::{SignedPublicKey, SignedSecretKey};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PgpError(pub String);

impl std::fmt::Display for PgpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for PgpError {}

impl From<pgp::errors::Error> for PgpError {
    fn from(e: pgp::errors::Error) -> Self {
        PgpError(e.to_string())
    }
}

pub const WRONG_PASSPHRASE: &str = "Wrong passphrase";

fn wrong_pw(_e: pgp::errors::Error) -> PgpError {
    PgpError(WRONG_PASSPHRASE.into())
}

/// A parsed key: public-only or with secret material.
#[derive(Debug, Clone)]
pub enum PgpKey {
    Public(SignedPublicKey),
    Secret(SignedSecretKey),
}

impl PgpKey {
    pub fn has_secret(&self) -> bool {
        matches!(self, PgpKey::Secret(_))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubkeyInfo {
    pub key_id: String,
    pub algorithm: String,
    pub size_or_curve: String,
    pub created_at: i64,
    pub usage: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyInfo {
    /// 40 (v4) / 64 (v6) uppercase hex chars.
    pub fingerprint: String,
    /// 16 uppercase hex chars (legacy key ID).
    pub key_id: String,
    pub algorithm: String,
    pub size_or_curve: String,
    /// Seconds since the UNIX epoch.
    pub created_at: i64,
    /// Seconds since the UNIX epoch; `None` = never expires.
    pub expires_at: Option<i64>,
    pub user_ids: Vec<String>,
    pub subkeys: Vec<SubkeyInfo>,
    pub has_secret: bool,
}

// ---------------------------------------------------------------------------
// Parse / export
// ---------------------------------------------------------------------------

/// Parse armored input containing one or more public and/or secret keys.
pub fn parse_keys(armored: &[u8]) -> Result<Vec<PgpKey>, PgpError> {
    let data = armored.to_vec();
    catch_unwind(AssertUnwindSafe(move || parse_keys_inner(&data)))
        .map_err(|_| PgpError("Malformed key data (parser crashed)".into()))?
}

/// Split input into armor blocks: `from_armor_many` reads multiple keys
/// inside one block but stops at the first `-----END`, and concatenated
/// `.asc` files (cat a.asc b.asc) are a common import shape.
fn split_armor_blocks(data: &[u8]) -> Vec<&[u8]> {
    const MARKER: &[u8] = b"-----BEGIN PGP";
    let mut starts = Vec::new();
    let mut i = 0;
    while i + MARKER.len() <= data.len() {
        if &data[i..i + MARKER.len()] == MARKER {
            starts.push(i);
            i += MARKER.len();
        } else {
            i += 1;
        }
    }
    if starts.len() <= 1 {
        return vec![data];
    }
    let mut blocks = Vec::with_capacity(starts.len());
    for (n, &start) in starts.iter().enumerate() {
        let end = starts.get(n + 1).copied().unwrap_or(data.len());
        blocks.push(&data[start..end]);
    }
    blocks
}

fn parse_keys_inner(armored: &[u8]) -> Result<Vec<PgpKey>, PgpError> {
    let mut keys = Vec::new();
    for block in split_armor_blocks(armored) {
        keys.extend(parse_armor_block(block)?);
    }
    if keys.is_empty() {
        return Err(PgpError("No PGP keys found in file".into()));
    }
    Ok(keys)
}

fn parse_armor_block(armored: &[u8]) -> Result<Vec<PgpKey>, PgpError> {
    let (iter, _headers) = PublicOrSecret::from_armor_many(Cursor::new(armored.to_vec()))
        .map_err(|e| PgpError(format!("Not a valid PGP armored file: {e}")))?;
    let mut keys = Vec::new();
    for item in iter {
        let item = item.map_err(|e| PgpError(format!("Malformed key in file: {e}")))?;
        let key = match item {
            PublicOrSecret::Public(pk) => {
                pk.verify_bindings()
                    .map_err(|e| PgpError(format!("Key failed signature verification: {e}")))?;
                PgpKey::Public(pk)
            }
            PublicOrSecret::Secret(sk) => {
                sk.verify_bindings()
                    .map_err(|e| PgpError(format!("Key failed signature verification: {e}")))?;
                PgpKey::Secret(sk)
            }
        };
        keys.push(key);
    }
    Ok(keys)
}

pub fn export_armored(key: &PgpKey) -> Result<String, PgpError> {
    match key {
        PgpKey::Public(pk) => Ok(pk.to_armored_string(ArmorOptions::default())?),
        PgpKey::Secret(sk) => Ok(sk.to_armored_string(ArmorOptions::default())?),
    }
}

/// Armored public key, stripping secret material if present.
pub fn export_public_armored(key: &PgpKey) -> Result<String, PgpError> {
    let pk = match key {
        PgpKey::Public(pk) => pk.clone(),
        PgpKey::Secret(sk) => sk.to_public_key(),
    };
    Ok(pk.to_armored_string(ArmorOptions::default())?)
}

// ---------------------------------------------------------------------------
// Key details
// ---------------------------------------------------------------------------

fn algo_strings(params: &PublicParams) -> (String, String) {
    fn curve_name(c: &ECCCurve) -> String {
        format!("{c:?}")
    }
    match params {
        PublicParams::RSA(p) => ("RSA".into(), format!("{} bits", p.key.n().bits())),
        PublicParams::DSA(_) => ("DSA".into(), String::new()),
        PublicParams::Elgamal(_) => ("ElGamal".into(), String::new()),
        PublicParams::ECDSA(p) => ("ECDSA".into(), curve_name(&p.curve())),
        PublicParams::ECDH(p) => ("ECDH".into(), curve_name(&p.curve())),
        PublicParams::EdDSALegacy(_) => ("EdDSA".into(), "Curve25519".into()),
        PublicParams::Ed25519(_) => ("EdDSA".into(), "Ed25519".into()),
        PublicParams::Ed448(_) => ("EdDSA".into(), "Ed448".into()),
        PublicParams::X25519(_) => ("ECDH".into(), "X25519".into()),
        PublicParams::X448(_) => ("ECDH".into(), "X448".into()),
        other => (format!("{other:?}"), String::new()),
    }
}

/// True if `sig` was issued by the key with the given fingerprint/key id.
fn is_self_sig(sig: &Signature, fpr: &Fingerprint, key_id: &pgp::types::KeyId) -> bool {
    if sig.issuer_fingerprint().iter().any(|f| *f == fpr) {
        return true;
    }
    sig.issuer_key_id().iter().any(|id| *id == key_id)
}

fn is_certification(sig: &Signature) -> bool {
    matches!(
        sig.typ(),
        Some(
            SignatureType::CertGeneric
                | SignatureType::CertPersona
                | SignatureType::CertCasual
                | SignatureType::CertPositive
        )
    )
}

/// The most recent self-certification across all user IDs — the signature
/// that carries the current key expiration and preferences.
fn latest_self_cert<'a>(
    users: &'a [SignedUser],
    fpr: &Fingerprint,
    key_id: &pgp::types::KeyId,
) -> Option<&'a Signature> {
    let mut best: Option<&Signature> = None;
    for user in users {
        for sig in &user.signatures {
            if is_certification(sig) && is_self_sig(sig, fpr, key_id) {
                if best.map_or(true, |b| sig.created() > b.created()) {
                    best = Some(sig);
                }
            }
        }
    }
    best
}

pub fn key_info(key: &PgpKey) -> KeyInfo {
    let (fpr, key_id, created, params, users) = match key {
        PgpKey::Public(pk) => (
            pk.primary_key.fingerprint(),
            pk.primary_key.legacy_key_id(),
            pk.primary_key.created_at(),
            pk.primary_key.public_params(),
            &pk.details.users,
        ),
        PgpKey::Secret(sk) => (
            sk.primary_key.fingerprint(),
            sk.primary_key.legacy_key_id(),
            sk.primary_key.created_at(),
            sk.primary_key.public_params(),
            &sk.details.users,
        ),
    };

    let (algorithm, size_or_curve) = algo_strings(params);
    let created_at = created.as_secs() as i64;
    let expires_at = latest_self_cert(users, &fpr, &key_id)
        .and_then(|sig| sig.key_expiration_time())
        .map(|d| created_at + d.as_secs() as i64);

    let user_ids = users
        .iter()
        .map(|u| String::from_utf8_lossy(u.id.id()).into_owned())
        .collect();

    let mut subkeys = Vec::new();
    let mut push_subkey = |key_id: pgp::types::KeyId,
                           created: Timestamp,
                           params: &PublicParams,
                           sigs: &[Signature]| {
        let (algorithm, size_or_curve) = algo_strings(params);
        let usage = sigs
            .first()
            .map(|s| {
                let f = s.key_flags();
                let mut parts = Vec::new();
                if f.certify() {
                    parts.push("certify");
                }
                if f.sign() {
                    parts.push("sign");
                }
                if f.encrypt_comms() || f.encrypt_storage() {
                    parts.push("encrypt");
                }
                if f.authentication() {
                    parts.push("auth");
                }
                parts.join("+")
            })
            .unwrap_or_default();
        subkeys.push(SubkeyInfo {
            key_id: format!("{key_id}").to_uppercase(),
            algorithm,
            size_or_curve,
            created_at: created.as_secs() as i64,
            usage,
        });
    };

    match key {
        PgpKey::Public(pk) => {
            for sub in &pk.public_subkeys {
                push_subkey(
                    sub.key.legacy_key_id(),
                    sub.key.created_at(),
                    sub.key.public_params(),
                    &sub.signatures,
                );
            }
        }
        PgpKey::Secret(sk) => {
            for sub in &sk.public_subkeys {
                push_subkey(
                    sub.key.legacy_key_id(),
                    sub.key.created_at(),
                    sub.key.public_params(),
                    &sub.signatures,
                );
            }
            for sub in &sk.secret_subkeys {
                push_subkey(
                    sub.key.legacy_key_id(),
                    sub.key.created_at(),
                    sub.key.public_params(),
                    &sub.signatures,
                );
            }
        }
    }

    KeyInfo {
        fingerprint: format!("{fpr:X}"),
        key_id: format!("{key_id}").to_uppercase(),
        algorithm,
        size_or_curve,
        created_at,
        expires_at,
        user_ids,
        subkeys,
        has_secret: key.has_secret(),
    }
}

// ---------------------------------------------------------------------------
// Generation
// ---------------------------------------------------------------------------

/// Generate an RSA sign+certify primary key with an RSA encryption subkey.
pub fn generate_rsa(
    bits: u32,
    name: &str,
    email: &str,
    passphrase: Option<&str>,
) -> Result<SignedSecretKey, PgpError> {
    let mut subkey = SubkeyParamsBuilder::default();
    subkey
        .key_type(KeyType::Rsa(bits))
        .can_encrypt(EncryptionCaps::All);
    if let Some(pw) = passphrase {
        subkey.passphrase(Some(pw.to_string()));
    }
    let subkey = subkey
        .build()
        .map_err(|e| PgpError(format!("Invalid subkey parameters: {e}")))?;

    let mut params = SecretKeyParamsBuilder::default();
    params
        .key_type(KeyType::Rsa(bits))
        .can_certify(true)
        .can_sign(true)
        .primary_user_id(format!("{name} <{email}>"))
        .subkeys(vec![subkey]);
    if let Some(pw) = passphrase {
        params.passphrase(Some(pw.to_string()));
    }
    let params = params
        .build()
        .map_err(|e| PgpError(format!("Invalid key parameters: {e}")))?;

    let key = params.generate(thread_rng())?;
    key.verify_bindings()?;
    Ok(key)
}

// ---------------------------------------------------------------------------
// Seed-derived keys
// ---------------------------------------------------------------------------

/// Fixed creation time for seed-derived keys (Bitcoin genesis block time).
/// The OpenPGP fingerprint commits to the creation timestamp, so this constant
/// MUST NEVER CHANGE or re-derived keys stop matching their originals.
pub const DERIVED_KEY_CREATED_AT: u32 = 1_231_006_505;

/// Domain-separation salt for the HKDF expansion of the device app-seed.
/// Versioned; bump only alongside a new derivation scheme, never in place.
const DERIVATION_SALT: &[u8] = b"prime-pgp-keychain/derive/v1";

/// Deterministically derive an Ed25519 (sign+certify) key with a Cv25519
/// encryption subkey from a 32-byte device app-seed and a key index.
///
/// Same seed + same index => byte-identical key material and fingerprint,
/// regardless of user ID or passphrase (the key is generated unprotected
/// from the deterministic stream; the passphrase is applied afterwards with
/// the system RNG so S2K salts never consume derivation bytes).
pub fn derive_ed25519(
    app_seed: &[u8; 32],
    index: u32,
    name: &str,
    email: &str,
    passphrase: Option<&str>,
) -> Result<SignedSecretKey, PgpError> {
    use hkdf::Hkdf;
    use rand_chacha::rand_core::SeedableRng;
    use sha2::Sha256;

    let hk = Hkdf::<Sha256>::new(Some(DERIVATION_SALT), app_seed);
    let mut key_seed = [0u8; 32];
    let mut info = Vec::with_capacity(12);
    info.extend_from_slice(b"pgp-key/");
    info.extend_from_slice(&index.to_le_bytes());
    hk.expand(&info, &mut key_seed)
        .map_err(|e| PgpError(format!("Key derivation failed: {e}")))?;
    let mut rng = rand_chacha::ChaCha20Rng::from_seed(key_seed);

    let created = Timestamp::from_secs(DERIVED_KEY_CREATED_AT);

    let subkey = SubkeyParamsBuilder::default()
        .key_type(KeyType::ECDH(ECCCurve::Curve25519Legacy))
        .can_encrypt(EncryptionCaps::All)
        .created_at(created)
        .build()
        .map_err(|e| PgpError(format!("Invalid subkey parameters: {e}")))?;

    let params = SecretKeyParamsBuilder::default()
        .key_type(KeyType::Ed25519Legacy)
        .can_certify(true)
        .can_sign(true)
        .created_at(created)
        .primary_user_id(format!("{name} <{email}>"))
        .subkeys(vec![subkey])
        .build()
        .map_err(|e| PgpError(format!("Invalid key parameters: {e}")))?;

    let key = params.generate(&mut rng)?;

    // Passphrase protection is applied outside the deterministic stream.
    let key = match passphrase {
        Some(pw) if !pw.is_empty() => {
            let mut sys_rng = thread_rng();
            let pw = Password::from(pw);
            let mut k = key;
            k.primary_key.set_password(&mut sys_rng, &pw)?;
            for sub in &mut k.secret_subkeys {
                sub.key.set_password(&mut sys_rng, &pw)?;
            }
            k
        }
        _ => key,
    };

    key.verify_bindings()?;
    Ok(key)
}

// ---------------------------------------------------------------------------
// Passphrase handling
// ---------------------------------------------------------------------------

fn to_password(pass: &str) -> Password {
    if pass.is_empty() {
        Password::empty()
    } else {
        Password::from(pass)
    }
}

/// Verify a passphrase against the primary secret key without mutating it.
pub fn check_passphrase(key: &SignedSecretKey, pass: &str) -> Result<(), PgpError> {
    let pw = to_password(pass);
    key.primary_key
        .unlock(&pw, |_, _| Ok(()))
        .map_err(wrong_pw)?
        .map_err(|e| PgpError(e.to_string()))
}

/// Re-encrypt all secret key material under a new passphrase.
/// `new = None` leaves the key unprotected.
pub fn change_passphrase(
    key: &SignedSecretKey,
    old: &str,
    new: Option<&str>,
) -> Result<SignedSecretKey, PgpError> {
    let old_pw = to_password(old);
    let mut k = key.clone();
    let mut rng = thread_rng();

    k.primary_key.remove_password(&old_pw).map_err(wrong_pw)?;
    if let Some(new) = new {
        k.primary_key
            .set_password(&mut rng, &Password::from(new))?;
    }
    for sub in &mut k.secret_subkeys {
        sub.key.remove_password(&old_pw).map_err(wrong_pw)?;
        if let Some(new) = new {
            sub.key.set_password(&mut rng, &Password::from(new))?;
        }
    }
    Ok(k)
}

// ---------------------------------------------------------------------------
// Data signing
// ---------------------------------------------------------------------------

/// Detached binary OpenPGP signature over `data` — raw signature-packet
/// bytes, the same shape `gpg --detach-sign` writes to a `.sig` file.
///
/// Signs with the primary key when its newest self-cert carries the sign
/// flag (all keys this app generates do), otherwise with the newest
/// signing-capable secret subkey. Primary and subkeys share one passphrase
/// everywhere in this app, so a single `pass` covers either signer.
pub fn sign_detached(
    key: &SignedSecretKey,
    pass: &str,
    data: &[u8],
) -> Result<Vec<u8>, PgpError> {
    Ok(make_detached_signature(key, pass, data)?.to_bytes()?)
}

/// Detached ASCII-armored OpenPGP signature over `data` — the same shape
/// `gpg --detach-sign --armor` writes to a `.asc` file. Text form, so it
/// survives QR codes, e-mail, and copy/paste.
pub fn sign_detached_armored(
    key: &SignedSecretKey,
    pass: &str,
    data: &[u8],
) -> Result<String, PgpError> {
    Ok(make_detached_signature(key, pass, data)?.to_armored_string(ArmorOptions::default())?)
}

fn make_detached_signature(
    key: &SignedSecretKey,
    pass: &str,
    data: &[u8],
) -> Result<DetachedSignature, PgpError> {
    let pw = to_password(pass);

    let fpr = key.primary_key.fingerprint();
    let key_id = key.primary_key.legacy_key_id();
    let primary_signs = latest_self_cert(&key.details.users, &fpr, &key_id)
        .map_or(true, |sig| sig.key_flags().sign());

    // Unlock explicitly first so a bad passphrase surfaces as
    // WRONG_PASSPHRASE instead of an opaque signing error.
    let signer: Box<&dyn SigningKey> = if primary_signs {
        key.primary_key
            .unlock(&pw, |_, _| Ok(()))
            .map_err(wrong_pw)?
            .map_err(|e| PgpError(e.to_string()))?;
        Box::new(&key.primary_key)
    } else {
        let sub = key
            .secret_subkeys
            .iter()
            .filter(|s| s.signatures.first().is_some_and(|b| b.key_flags().sign()))
            .max_by_key(|s| s.key.created_at().as_secs())
            .ok_or_else(|| PgpError("Key has no signing-capable secret key".into()))?;
        sub.key
            .unlock(&pw, |_, _| Ok(()))
            .map_err(wrong_pw)?
            .map_err(|e| PgpError(e.to_string()))?;
        Box::new(&sub.key)
    };

    let hash = signer.hash_alg();
    Ok(DetachedSignature::sign_binary_data(thread_rng(), &signer, &pw, hash, data)?)
}

// ---------------------------------------------------------------------------
// Self-signature editing (expiration, user IDs)
// ---------------------------------------------------------------------------

/// Rebuild the self-certification for one user ID, copying preferences from
/// the current newest self-cert and setting the given expiration.
fn resign_user_id(
    key: &SignedSecretKey,
    pass: &Password,
    uid: &UserId,
    template: Option<&Signature>,
    expiry_secs_from_creation: Option<u32>,
    is_primary: bool,
) -> Result<Signature, PgpError> {
    let primary = &key.primary_key;
    let mut rng = thread_rng();

    let mut config = SignatureConfig::from_key(&mut rng, primary, SignatureType::CertPositive)?;

    let mut hashed = vec![
        Subpacket::regular(SubpacketData::SignatureCreationTime(Timestamp::now()))?,
        Subpacket::regular(SubpacketData::IssuerFingerprint(primary.fingerprint()))?,
    ];
    if let Some(t) = template {
        hashed.push(Subpacket::regular(SubpacketData::KeyFlags(t.key_flags()))?);
        if let Some(features) = t.features() {
            hashed.push(Subpacket::regular(SubpacketData::Features(
                features.clone(),
            ))?);
        }
        let sym = t.preferred_symmetric_algs();
        if !sym.is_empty() {
            hashed.push(Subpacket::regular(
                SubpacketData::PreferredSymmetricAlgorithms(sym.iter().copied().collect()),
            )?);
        }
        let hash = t.preferred_hash_algs();
        if !hash.is_empty() {
            hashed.push(Subpacket::regular(SubpacketData::PreferredHashAlgorithms(
                hash.iter().copied().collect(),
            ))?);
        }
        let comp = t.preferred_compression_algs();
        if !comp.is_empty() {
            hashed.push(Subpacket::regular(
                SubpacketData::PreferredCompressionAlgorithms(comp.iter().copied().collect()),
            )?);
        }
    } else {
        // No prior self-sig to copy from: certify+sign primary flags.
        let mut flags = pgp::packet::KeyFlags::default();
        flags.set_certify(true);
        flags.set_sign(true);
        hashed.push(Subpacket::regular(SubpacketData::KeyFlags(flags))?);
    }
    if let Some(secs) = expiry_secs_from_creation {
        hashed.push(Subpacket::regular(SubpacketData::KeyExpirationTime(
            PgpDuration::from_secs(secs),
        ))?);
    }
    if is_primary {
        hashed.push(Subpacket::regular(SubpacketData::IsPrimary(true))?);
    }
    config.hashed_subpackets = hashed;

    if primary.version() <= KeyVersion::V4 {
        config.unhashed_subpackets = vec![Subpacket::regular(SubpacketData::IssuerKeyId(
            primary.legacy_key_id(),
        ))?];
    }

    let sig = config.sign_certification(primary, primary.public_key(), pass, uid.tag(), uid)?;
    Ok(sig)
}

/// Replace every user ID's self-certification, setting the key expiration.
/// `days_from_now = None` clears the expiration ("never expires").
pub fn set_expiration(
    key: &SignedSecretKey,
    pass: &str,
    days_from_now: Option<u32>,
    now_epoch: i64,
) -> Result<SignedSecretKey, PgpError> {
    let pw = to_password(pass);
    check_passphrase(key, pass)?;

    let created = key.primary_key.created_at().as_secs() as i64;
    let expiry_secs_from_creation = match days_from_now {
        None => None,
        Some(days) => {
            let expires_epoch = now_epoch + i64::from(days) * 86_400;
            let secs = expires_epoch - created;
            if secs <= 0 {
                return Err(PgpError("Expiration would be in the past".into()));
            }
            Some(
                u32::try_from(secs)
                    .map_err(|_| PgpError("Expiration too far in the future".into()))?,
            )
        }
    };

    let fpr = key.primary_key.fingerprint();
    let key_id = key.primary_key.legacy_key_id();
    let template = latest_self_cert(&key.details.users, &fpr, &key_id).cloned();

    let mut k = key.clone();
    for (i, user) in k.details.users.iter_mut().enumerate() {
        let sig = resign_user_id(
            key,
            &pw,
            &user.id,
            template.as_ref(),
            expiry_secs_from_creation,
            i == 0,
        )?;
        // Keep third-party certifications, replace our self-signatures.
        user.signatures
            .retain(|s| !is_self_sig(s, &fpr, &key_id));
        user.signatures.push(sig);
    }

    k.verify_bindings()?;
    Ok(k)
}

/// Add a user ID, self-certified with the key's current expiration/prefs.
pub fn add_user_id(
    key: &SignedSecretKey,
    pass: &str,
    name: &str,
    email: &str,
) -> Result<SignedSecretKey, PgpError> {
    let pw = to_password(pass);
    check_passphrase(key, pass)?;

    let uid = UserId::from_str(Default::default(), format!("{name} <{email}>"))
        .map_err(|e| PgpError(format!("Invalid user ID: {e}")))?;

    let fpr = key.primary_key.fingerprint();
    let key_id = key.primary_key.legacy_key_id();
    let template = latest_self_cert(&key.details.users, &fpr, &key_id).cloned();
    // Carry the current expiration over so gpg computes a consistent expiry
    // across all user IDs.
    let expiry = template.as_ref().and_then(|t| t.key_expiration_time());

    let sig = resign_user_id(
        key,
        &pw,
        &uid,
        template.as_ref(),
        expiry.map(|d| d.as_secs()),
        false,
    )?;

    let mut k = key.clone();
    k.details.users.push(uid.into_signed(sig));
    k.verify_bindings()?;
    Ok(k)
}

/// Remove the user ID at `index`. Refuses to remove the last one.
pub fn remove_user_id(key: &SignedSecretKey, index: usize) -> Result<SignedSecretKey, PgpError> {
    if key.details.users.len() <= 1 {
        return Err(PgpError("Cannot remove the last user ID".into()));
    }
    if index >= key.details.users.len() {
        return Err(PgpError("No such user ID".into()));
    }
    let mut k = key.clone();
    k.details.users.remove(index);
    k.verify_bindings()?;
    Ok(k)
}
