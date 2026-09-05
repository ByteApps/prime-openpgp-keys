//! UI-free OpenPGP operations for the OpenPGP Keys app (formerly "PGP Keychain").
//!
//! Lives in its own crate so it can be unit-tested with plain `cargo test
//! -p pgp-core` on the host — the app crate itself only compiles through the
//! `foundation` CLI (Slint `@ui/` imports).
//!
//! All armor parsing runs behind `catch_unwind`: rpgp has a history of panics
//! on crafted packets (CVE-2026-21895) and imported `.asc` files are
//! untrusted input.
//!
//! # Editing takes the key BY VALUE — never clone a key on device
//!
//! `SignedSecretKey::clone` compiles to a **177 KB stack frame** on
//! `armv7a-unknown-xous-elf`, and it calls `PublicParams::clone` (**145 KB**).
//! KeyOS gives a process a **256 KB** stack (`STACK_PAGE_COUNT = 64` x 4 KB),
//! so a single `key.clone()` inside an editing operation overflows it:
//! 177 + 145 = 322 KB. The device reports
//! `Invalid memory access (L2) ... 0x109b8 bytes below stack` and the app
//! dies with exit code 255.
//!
//! The frames are that large because the derived `Clone` for `PublicParams`
//! materialises every `draft-pqc` variant (ML-DSA-87, SLH-DSA, ML-KEM-1024)
//! in one frame, each arm getting its own stack slot. The enum itself is only
//! 304 bytes — `size_of` tells you nothing here; measure the ARM frame with
//! `scripts/check-stack-frames.sh`.
//!
//! So `set_expiration`, `add_user_id`, `remove_user_id` and
//! `change_passphrase` all take `key: SignedSecretKey` **by value** and mutate
//! it in place. Do not "simplify" any of them back to `&SignedSecretKey` +
//! `key.clone()`, and do not add a `.clone()` on a key type anywhere the app
//! can reach: **the simulator cannot catch this** (a macOS thread has an 8 MB
//! stack, so every one of these paths passes there).

use std::io::Cursor;
use std::panic::{catch_unwind, AssertUnwindSafe};

/// Imported-seed root derivation (PLAN-openpgp-keys-import.md §2):
/// BIP-39 mnemonic + optional passphrase -> the portable, cross-platform
/// root this app persists (sealed at rest — see `store`, U3).
pub mod import;
/// Sealing/opening the imported-seed root at rest (PLAN-openpgp-keys-import.md
/// §4). Pure functions of the sealing seed — the app layer reads/writes the
/// AppData file.
pub mod store;

use hkdf::Hkdf;
use pgp::composed::{
    ArmorOptions, DetachedSignature, KeyType, Message, MessageBuilder, PublicOrSecret,
    SignedKeyDetails, SignedSecretSubKey,
};
use pgp::crypto::ecc_curve::ECCCurve;
use pgp::crypto::hash::HashAlgorithm;
use pgp::crypto::sym::SymmetricKeyAlgorithm;
// `pgp::crypto::rsa` is deliberately referenced by full path (`pgp::crypto::rsa::SecretKey`)
// rather than `use`d here: the RustCrypto `rsa` crate (imported below for
// `PublicKeyParts`) already owns the bare name `rsa` in this module.
use pgp::crypto::{ecdh, ecdsa, ed25519, eddsa_legacy, ml_kem768_x25519};
use pgp::packet::{
    Features, KeyFlags, Notation, PacketTrait, PubKeyInner, PublicKey, PublicSubkey, SecretKey,
    SecretSubkey, Signature, SignatureConfig, SignatureType, Subpacket, SubpacketData, UserId,
};
use pgp::ser::Serialize as _;
use pgp::types::{
    CompressionAlgorithm, Duration as PgpDuration, Fingerprint, KeyDetails as _, KeyVersion,
    Password, PlainSecretParams, PublicParams, SecretParams, SignedUser, SigningKey, Timestamp,
};
use rand::thread_rng;
use rsa::traits::PublicKeyParts;
use sha2::Sha256;

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
    /// Parsed `derived@byteapps.com` notation from the latest primary
    /// self-certification, if present (PLAN-openpgp-keys-import.md §6).
    /// `None` for random keys, foreign keys, and keys with a malformed or
    /// absent notation.
    pub provenance: Option<Provenance>,
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
    match key {
        PgpKey::Public(pk) => Ok(pk.to_armored_string(ArmorOptions::default())?),
        PgpKey::Secret(sk) => Ok(sk.to_public_key().to_armored_string(ArmorOptions::default())?),
    }
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

    let provenance = latest_self_cert(users, &fpr, &key_id).and_then(provenance_from_cert);

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
        provenance,
    }
}

// ---------------------------------------------------------------------------
// Provenance (PLAN-openpgp-keys-import.md §6)
//
// A derived key's primary self-certification carries a `derived@byteapps.com`
// notation recording which imported-seed root and index produced it, so any
// importer — including a future desktop/mobile app — can tell where a
// derived key came from without guesswork. The notation lives in the HASHED
// subpackets (it is bound by the signature) but is otherwise inert: it never
// touches the public key packet, so it cannot move a fingerprint.
// ---------------------------------------------------------------------------

/// Notation name used to mark a derived key's primary self-certification.
const PROVENANCE_NOTATION_NAME: &str = "derived@byteapps.com";

/// Which HKDF stream (`ed25519/...` vs `p521/...`) produced a derived key —
/// the `alg` field of the provenance notation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DerivedAlg {
    Ed25519,
    P521,
}

impl DerivedAlg {
    fn as_str(self) -> &'static str {
        match self {
            DerivedAlg::Ed25519 => "ed25519",
            DerivedAlg::P521 => "p521",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        match s {
            "ed25519" => Some(DerivedAlg::Ed25519),
            "p521" => Some(DerivedAlg::P521),
            _ => None,
        }
    }
}

/// Parsed `derived@byteapps.com` notation: which imported-seed root and
/// index produced a derived key. See [`provenance`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Provenance {
    /// Notation format version. Always `1` today — [`provenance`] returns
    /// `None` for any other value rather than guessing at its shape.
    pub version: u8,
    pub root_id: [u8; 4],
    pub index: u32,
    pub alg: DerivedAlg,
}

/// Render the notation value string: `v1;root=<8 upper-hex>;idx=<index>;alg=<alg>`.
fn provenance_notation_value(root_id: &[u8; 4], index: u32, alg: DerivedAlg) -> String {
    format!(
        "v1;root={:02X}{:02X}{:02X}{:02X};idx={index};alg={}",
        root_id[0],
        root_id[1],
        root_id[2],
        root_id[3],
        alg.as_str()
    )
}

/// Build the hashed `derived@byteapps.com` notation subpacket for a freshly
/// derived key's primary self-certification.
fn provenance_notation_subpacket(
    root_id: &[u8; 4],
    index: u32,
    alg: DerivedAlg,
) -> Result<Subpacket, PgpError> {
    Ok(Subpacket::regular(SubpacketData::Notation(Notation {
        readable: true,
        name: PROVENANCE_NOTATION_NAME.into(),
        value: provenance_notation_value(root_id, index, alg).into(),
    }))?)
}

/// Parse a notation value string (`v1;root=...;idx=...;alg=...`) into a
/// [`Provenance`]. Any deviation from the exact expected shape — wrong
/// version, non-hex/wrong-length root, unparseable index, unknown algorithm,
/// a missing or duplicated field, or extra junk — returns `None` rather than
/// guessing. Never panics on untrusted input.
fn parse_provenance_value(value: &str) -> Option<Provenance> {
    let mut root_id: Option<[u8; 4]> = None;
    let mut index: Option<u32> = None;
    let mut alg: Option<DerivedAlg> = None;

    let mut fields = value.split(';');
    if fields.next()? != "v1" {
        return None;
    }
    for field in fields {
        let (key, val) = field.split_once('=')?;
        match key {
            "root" => {
                if root_id.is_some() || val.len() != 8 {
                    return None;
                }
                let mut bytes = [0u8; 4];
                for (i, b) in bytes.iter_mut().enumerate() {
                    *b = u8::from_str_radix(val.get(i * 2..i * 2 + 2)?, 16).ok()?;
                }
                root_id = Some(bytes);
            }
            "idx" => {
                if index.is_some() {
                    return None;
                }
                index = Some(val.parse().ok()?);
            }
            "alg" => {
                if alg.is_some() {
                    return None;
                }
                alg = Some(DerivedAlg::parse(val)?);
            }
            _ => return None,
        }
    }

    Some(Provenance {
        version: 1,
        root_id: root_id?,
        index: index?,
        alg: alg?,
    })
}

/// Extract and parse the `derived@byteapps.com` notation from one
/// self-certification, if present and well-formed.
fn provenance_from_cert(sig: &Signature) -> Option<Provenance> {
    let notation = sig
        .notations()
        .into_iter()
        .find(|n| n.name.as_ref() == PROVENANCE_NOTATION_NAME.as_bytes())?;
    let value = std::str::from_utf8(notation.value.as_ref()).ok()?;
    parse_provenance_value(value)
}

/// Which imported-seed root and index produced this key, if it was
/// deterministically derived and its notation is intact. `None` for random
/// keys ([`generate_ed25519`] etc.), foreign/imported keys, and any key
/// whose notation value doesn't parse.
pub fn provenance(key: &PgpKey) -> Option<Provenance> {
    let (fpr, key_id, users) = match key {
        PgpKey::Public(pk) => (
            pk.primary_key.fingerprint(),
            pk.primary_key.legacy_key_id(),
            &pk.details.users,
        ),
        PgpKey::Secret(sk) => (
            sk.primary_key.fingerprint(),
            sk.primary_key.legacy_key_id(),
            &sk.details.users,
        ),
    };
    let sig = latest_self_cert(users, &fpr, &key_id)?;
    provenance_from_cert(sig)
}

// ---------------------------------------------------------------------------
// Generation
// ---------------------------------------------------------------------------

/// Generate an RSA sign+certify primary key with an RSA encryption subkey.
///
/// Builds raw key material directly with rpgp's per-algorithm generator
/// (`pgp::crypto::rsa::SecretKey::generate`) and hands it to [`assemble_key`]
/// instead of `SecretKeyParamsBuilder`/`SecretKeyParams::generate()` — see the
/// module doc comment on the device stack budget: the builder's `generate()`
/// is one giant `match` over every rpgp key type (including the v6-only
/// `draft-pqc` signature algorithms this app never uses), and LLVM inlines
/// enough of it into a single frame to overflow KeyOS's 256 KB process stack.
/// Every key this crate creates now goes through the same shallow assembly
/// path as the seed-derived keys below.
pub fn generate_rsa(
    bits: u32,
    name: &str,
    email: &str,
    passphrase: Option<&str>,
) -> Result<SignedSecretKey, PgpError> {
    let primary_secret = pgp::crypto::rsa::SecretKey::generate(thread_rng(), bits as usize)?;
    let primary_public_params = PublicParams::RSA((&primary_secret).into());
    let primary_secret_params = PlainSecretParams::RSA(primary_secret);

    let sub_secret = pgp::crypto::rsa::SecretKey::generate(thread_rng(), bits as usize)?;
    let sub_public_params = PublicParams::RSA((&sub_secret).into());
    let sub_secret_params = PlainSecretParams::RSA(sub_secret);

    let key = assemble_key(
        KeyType::Rsa(bits).to_alg(),
        primary_public_params,
        primary_secret_params,
        KeyType::Rsa(bits).to_alg(),
        sub_public_params,
        sub_secret_params,
        name,
        email,
        Timestamp::now(),
        None,
    )?;
    apply_passphrase(key, passphrase)
}

/// NIST prime curve for [`generate_nistp`], strongest last.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NistCurve {
    /// secp256r1, ~128-bit security.
    P256,
    /// secp384r1, ~192-bit security (CNSA).
    P384,
    /// secp521r1, ~256-bit security.
    P521,
}

impl NistCurve {
    fn ecc(self) -> ECCCurve {
        match self {
            NistCurve::P256 => ECCCurve::P256,
            NistCurve::P384 => ECCCurve::P384,
            NistCurve::P521 => ECCCurve::P521,
        }
    }
}

/// Generate a NIST P-521 pair — see [`generate_nistp`].
pub fn generate_p521(
    name: &str,
    email: &str,
    passphrase: Option<&str>,
) -> Result<SignedSecretKey, PgpError> {
    generate_nistp(NistCurve::P521, name, email, passphrase)
}

/// Generate a NIST-curve sign+certify primary key (ECDSA) with a same-curve
/// ECDH encryption subkey.
///
/// P-521 is the strongest classical pair this crate offers (~256-bit
/// security vs ~128 for Curve25519 and ~140 for RSA-4096). All three curves
/// interop as ordinary v4 RFC 6637 keys with GnuPG >= 2.1; signatures hash
/// with SHA-512/384 via the advertised preferences.
pub fn generate_nistp(
    curve: NistCurve,
    name: &str,
    email: &str,
    passphrase: Option<&str>,
) -> Result<SignedSecretKey, PgpError> {
    let primary_secret = ecdsa::SecretKey::generate(thread_rng(), &curve.ecc())?;
    let primary_public_params = PublicParams::ECDSA((&primary_secret).try_into()?);
    let primary_secret_params = PlainSecretParams::ECDSA(primary_secret);

    let sub_secret = ecdh::SecretKey::generate(thread_rng(), &curve.ecc())?;
    let sub_public_params = PublicParams::ECDH((&sub_secret).try_into()?);
    let sub_secret_params = PlainSecretParams::ECDH(sub_secret);

    let key = assemble_key(
        KeyType::ECDSA(curve.ecc()).to_alg(),
        primary_public_params,
        primary_secret_params,
        KeyType::ECDH(curve.ecc()).to_alg(),
        sub_public_params,
        sub_secret_params,
        name,
        email,
        Timestamp::now(),
        None,
    )?;
    apply_passphrase(key, passphrase)
}

/// Generate a random Ed25519 sign+certify primary key with a Cv25519
/// encryption subkey — the same pair "From seed" derives, but from the
/// system RNG. v4 "legacy" EdDSA/ECDH format for GnuPG 2.2 interop.
pub fn generate_ed25519(
    name: &str,
    email: &str,
    passphrase: Option<&str>,
) -> Result<SignedSecretKey, PgpError> {
    let primary_secret = ed25519::SecretKey::generate(thread_rng(), ed25519::Mode::EdDSALegacy);
    let primary_public_params = PublicParams::EdDSALegacy((&primary_secret).into());
    let primary_secret_params =
        PlainSecretParams::EdDSALegacy(eddsa_legacy::SecretKey::Ed25519(primary_secret));

    let sub_secret = ecdh::SecretKey::generate(thread_rng(), &ECCCurve::Curve25519Legacy)?;
    let sub_public_params = PublicParams::ECDH((&sub_secret).try_into()?);
    let sub_secret_params = PlainSecretParams::ECDH(sub_secret);

    let key = assemble_key(
        KeyType::Ed25519Legacy.to_alg(),
        primary_public_params,
        primary_secret_params,
        KeyType::ECDH(ECCCurve::Curve25519Legacy).to_alg(),
        sub_public_params,
        sub_secret_params,
        name,
        email,
        Timestamp::now(),
        None,
    )?;
    apply_passphrase(key, passphrase)
}

/// Generate a post-quantum hybrid key: Ed25519 sign+certify primary with an
/// ML-KEM-768+X25519 composite encryption subkey (RFC 9980, algorithm 35).
///
/// Algorithm 35 is the one RFC 9980 algorithm permitted on v4 keys, which
/// keeps this key compatible with the app's v4 world: the encryption is
/// post-quantum (harvest-now-decrypt-later resistant), the signature half
/// stays classical Ed25519 (the ML-DSA algorithms are v6-only). Only
/// RFC 9980-aware software can encrypt to or decrypt with the subkey;
/// older GnuPG imports the key, signs/verifies with the primary, and warns
/// about the unknown subkey algorithm.
pub fn generate_pqc_hybrid(
    name: &str,
    email: &str,
    passphrase: Option<&str>,
) -> Result<SignedSecretKey, PgpError> {
    let primary_secret = ed25519::SecretKey::generate(thread_rng(), ed25519::Mode::EdDSALegacy);
    let primary_public_params = PublicParams::EdDSALegacy((&primary_secret).into());
    let primary_secret_params =
        PlainSecretParams::EdDSALegacy(eddsa_legacy::SecretKey::Ed25519(primary_secret));

    let sub_secret = ml_kem768_x25519::SecretKey::generate(thread_rng());
    let sub_public_params = PublicParams::MlKem768X25519((&sub_secret).into());
    let sub_secret_params = PlainSecretParams::MlKem768X25519(sub_secret);

    let key = assemble_key(
        KeyType::Ed25519Legacy.to_alg(),
        primary_public_params,
        primary_secret_params,
        KeyType::MlKem768X25519.to_alg(),
        sub_public_params,
        sub_secret_params,
        name,
        email,
        Timestamp::now(),
        None,
    )?;
    apply_passphrase(key, passphrase)
}

/// Strongest-first symmetric algorithm preference list — shared by
/// [`sign_primary_self_cert`] (every key this crate creates, random or
/// derived) so all paths advertise the same thing.
fn preferred_symmetric_algorithms() -> Vec<SymmetricKeyAlgorithm> {
    vec![
        SymmetricKeyAlgorithm::AES256,
        SymmetricKeyAlgorithm::AES192,
        SymmetricKeyAlgorithm::AES128,
    ]
}

fn preferred_hash_algorithms() -> Vec<HashAlgorithm> {
    vec![
        HashAlgorithm::Sha512,
        HashAlgorithm::Sha384,
        HashAlgorithm::Sha256,
        HashAlgorithm::Sha224,
    ]
}

fn preferred_compression_algorithms() -> Vec<CompressionAlgorithm> {
    vec![
        CompressionAlgorithm::ZLIB,
        CompressionAlgorithm::ZIP,
        CompressionAlgorithm::Uncompressed,
    ]
}

// ---------------------------------------------------------------------------
// Seed-derived keys
// ---------------------------------------------------------------------------

/// Fixed creation time for seed-derived keys (Bitcoin genesis block time).
/// The OpenPGP fingerprint commits to the creation timestamp, so this constant
/// MUST NEVER CHANGE or re-derived keys stop matching their originals.
pub const DERIVED_KEY_CREATED_AT: u32 = 1_231_006_505;

/// HKDF-SHA256 salt for the per-key expansion of the imported-seed root
/// (PLAN-openpgp-keys-import.md §2.3). This is a **cross-platform contract**:
/// a future desktop/mobile OpenPGP Keys app must derive byte-identical keys
/// from the same root + index using this exact salt/info scheme, so the
/// derivation is specified as raw key bytes rather than "whatever rpgp's
/// RNG-driven generator does" (the old, rpgp-only scheme this replaced).
/// Versioned; bump only alongside a new derivation scheme, never in place.
const KEY_DERIVATION_SALT: &[u8] = b"com.byteapps.openpgp-keys/key/v1";

/// `HKDF-Extract(salt = KEY_DERIVATION_SALT, IKM = root)`, ready for the
/// per-algorithm `HKDF-Expand` calls below.
fn key_prk(root: &[u8; 32]) -> Hkdf<Sha256> {
    Hkdf::<Sha256>::new(Some(KEY_DERIVATION_SALT), root)
}

/// `prefix || LE32(index) || suffix`, the HKDF `info` parameter shape shared
/// by every per-key expansion in §2.3.
fn hkdf_info(prefix: &[u8], index: u32, suffix: &[u8]) -> Vec<u8> {
    let mut info = Vec::with_capacity(prefix.len() + 4 + suffix.len());
    info.extend_from_slice(prefix);
    info.extend_from_slice(&index.to_le_bytes());
    info.extend_from_slice(suffix);
    info
}

fn expand<const N: usize>(prk: &Hkdf<Sha256>, info: &[u8]) -> Result<[u8; N], PgpError> {
    let mut out = [0u8; N];
    prk.expand(info, &mut out)
        .map_err(|e| PgpError(format!("Key derivation failed: {e}")))?;
    Ok(out)
}

// -- RFC 7748 clamping for the X25519 subkey scalar --------------------------

/// Clamp a raw 32-byte value into a valid X25519 scalar per RFC 7748 §5:
/// clear the low 3 bits, clear the top bit, set the second-highest bit. This
/// is the canonical private-scalar representation every X25519
/// implementation produces from raw entropy (x25519-dalek itself clamps
/// again, idempotently, whenever the scalar is actually used), so the
/// derived subkey's *exported* secret bytes match what any other library
/// would store for the same `enc_key` — not just its public point.
fn clamp_x25519(mut k: [u8; 32]) -> [u8; 32] {
    k[0] &= 0b1111_1000;
    k[31] &= 0b0111_1111;
    k[31] |= 0b0100_0000;
    k
}

// -- Big-endian modular reduction for the P-521 scalar -----------------------
//
// No bignum crate: this is a single fixed-width (640-bit / 528-bit) binary
// long division, easier to review and to cross-check byte-for-byte against
// an independent implementation (tests/derive.rs does so with `num-bigint`)
// than a generic-width dependency would be.

/// NIST P-521 group order `n`, big-endian, 66 bytes (SEC 2 §2.6.2 / FIPS
/// 186-4 D.1.2.5).
const P521_ORDER: [u8; 66] = [
    0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xfa, 0x51, 0x86, 0x87, 0x83, 0xbf, 0x2f, 0x96, 0x6b, 0x7f, 0xcc, 0x01, 0x48, 0xf7, 0x09,
    0xa5, 0xd0, 0x3b, 0xb5, 0xc9, 0xb8, 0x89, 0x9c, 0x47, 0xae, 0xbb, 0x6f, 0xb7, 0x1e, 0x91, 0x38,
    0x64, 0x09,
];

/// True if the big-endian byte string `a` is >= `b` (equal length).
fn be_ge(a: &[u8], b: &[u8]) -> bool {
    a.iter().cmp(b.iter()) != std::cmp::Ordering::Less
}

/// `a -= b` in place, both big-endian, equal length; caller guarantees
/// `a >= b` (no underflow).
fn be_sub_assign(a: &mut [u8], b: &[u8]) {
    let mut borrow = 0i16;
    for i in (0..a.len()).rev() {
        let diff = i16::from(a[i]) - i16::from(b[i]) - borrow;
        if diff < 0 {
            a[i] = (diff + 256) as u8;
            borrow = 1;
        } else {
            a[i] = diff as u8;
            borrow = 0;
        }
    }
}

/// `a += 1` in place, big-endian; caller guarantees no overflow.
fn be_add_one(a: &mut [u8]) {
    for byte in a.iter_mut().rev() {
        let (sum, carry) = byte.overflowing_add(1);
        *byte = sum;
        if !carry {
            return;
        }
    }
}

/// `int_be(raw) mod int_be(modulus)`, both interpreted as big-endian
/// integers of the same byte length. Binary long division, MSB-first: shifts
/// one bit of `raw` into a running remainder and conditionally subtracts
/// `modulus`. `raw` and `modulus` must be the same length; the result is
/// that same length (small values keep their leading zero bytes).
fn be_reduce(raw: &[u8], modulus: &[u8]) -> Vec<u8> {
    debug_assert_eq!(raw.len(), modulus.len());
    let mut rem = vec![0u8; raw.len()];
    for &byte in raw {
        for bit in (0..8).rev() {
            let mut carry = (byte >> bit) & 1;
            for b in rem.iter_mut().rev() {
                let next_carry = *b >> 7;
                *b = (*b << 1) | carry;
                carry = next_carry;
            }
            if be_ge(&rem, modulus) {
                be_sub_assign(&mut rem, modulus);
            }
        }
    }
    rem
}

/// FIPS 186-4 B.4.1-style scalar derivation: 80 bytes of HKDF output
/// (640 bits, 74 more than the 66-byte field size) reduced modulo `n - 1`
/// and shifted into `[1, n-1]`, where `n` is the P-521 group order. The extra
/// bits over the field size make the modulo bias on `[0, n-2]` negligible
/// (below 2^-119).
fn p521_scalar_from_raw(raw: &[u8; 80]) -> [u8; 66] {
    let mut n_minus_1 = P521_ORDER;
    let mut one = [0u8; 66];
    one[65] = 1;
    be_sub_assign(&mut n_minus_1, &one);

    let mut modulus = [0u8; 80];
    modulus[80 - 66..].copy_from_slice(&n_minus_1);

    let rem = be_reduce(raw, &modulus);
    let mut scalar = [0u8; 66];
    scalar.copy_from_slice(&rem[80 - 66..]);
    be_add_one(&mut scalar);
    scalar
}

/// Build a validated P-521 secret scalar from 80 bytes of HKDF output. Never
/// errors in practice (the reduction always lands in `[1, n-1]`); the
/// `Result` exists because `p521::SecretKey::from_slice` returns one.
fn p521_secret_key(raw: [u8; 80]) -> Result<p521::SecretKey, PgpError> {
    let scalar = p521_scalar_from_raw(&raw);
    p521::SecretKey::from_slice(&scalar)
        .map_err(|e| PgpError(format!("Invalid P-521 scalar: {e}")))
}

// -- Self-signing helpers -----------------------------------------------------
//
// Deliberately NOT `composed::KeyDetails::sign`/`PublicSubkey::sign` (what
// `SecretKeyParams::generate()` uses internally): those hardcode
// `Timestamp::now()` for the self-signature's creation time, which would
// make every re-derivation produce a different armored export even though
// the fingerprint stayed the same. Pinning the self-signature's creation
// time to `DERIVED_KEY_CREATED_AT` too makes the whole export byte-identical
// across re-derivations (S2K passphrase salts aside) — same pattern the
// existing `resign_user_id` below already uses for post-hoc re-signing.

/// Self-certify the primary user ID: certify+sign key flags, the algorithm
/// preferences every key this crate makes advertises, a fixed creation time
/// so re-deriving the same root+index reproduces this signature byte for
/// byte (ECDSA/EdDSA signing here is otherwise deterministic already), and —
/// for a derived key only — the `derived@byteapps.com` provenance notation
/// (PLAN-openpgp-keys-import.md §6) recording the root/index/algorithm that
/// produced it. `provenance` is `None` for the random-keygen paths
/// (`generate_rsa` etc.): no notation on those, so [`provenance`] (the query
/// function) correctly reports `None` for them.
fn sign_primary_self_cert(
    primary: &SecretKey,
    uid: &UserId,
    created: Timestamp,
    provenance: Option<(&[u8; 4], u32, DerivedAlg)>,
) -> Result<Signature, PgpError> {
    let mut rng = thread_rng();
    let mut config = SignatureConfig::from_key(&mut rng, primary, SignatureType::CertPositive)?;

    let mut keyflags = KeyFlags::default();
    keyflags.set_certify(true);
    keyflags.set_sign(true);
    let mut features = Features::default();
    features.set_seipd_v1(true);

    let mut hashed_subpackets = vec![
        Subpacket::regular(SubpacketData::SignatureCreationTime(created))?,
        Subpacket::regular(SubpacketData::IssuerFingerprint(primary.fingerprint()))?,
        Subpacket::regular(SubpacketData::KeyFlags(keyflags))?,
        Subpacket::regular(SubpacketData::Features(features))?,
        Subpacket::regular(SubpacketData::PreferredSymmetricAlgorithms(
            preferred_symmetric_algorithms().into(),
        ))?,
        Subpacket::regular(SubpacketData::PreferredHashAlgorithms(
            preferred_hash_algorithms().into(),
        ))?,
        Subpacket::regular(SubpacketData::PreferredCompressionAlgorithms(
            preferred_compression_algorithms().into(),
        ))?,
        Subpacket::regular(SubpacketData::IsPrimary(true))?,
    ];
    if let Some((root_id, index, alg)) = provenance {
        hashed_subpackets.push(provenance_notation_subpacket(root_id, index, alg)?);
    }
    config.hashed_subpackets = hashed_subpackets;
    config.unhashed_subpackets = vec![Subpacket::regular(SubpacketData::IssuerKeyId(
        primary.legacy_key_id(),
    ))?];

    let pw = Password::empty();
    Ok(config.sign_certification(primary, primary.public_key(), &pw, uid.tag(), uid)?)
}

/// Bind the encryption subkey to the primary with a Subkey Binding Signature
/// (type 0x18), again at the fixed creation time.
fn sign_subkey_binding(
    primary: &SecretKey,
    sub_pub: &PublicSubkey,
    created: Timestamp,
) -> Result<Signature, PgpError> {
    let mut rng = thread_rng();
    let mut config = SignatureConfig::from_key(&mut rng, primary, SignatureType::SubkeyBinding)?;

    let mut keyflags = KeyFlags::default();
    keyflags.set_encrypt_comms(true);
    keyflags.set_encrypt_storage(true);

    config.hashed_subpackets = vec![
        Subpacket::regular(SubpacketData::SignatureCreationTime(created))?,
        Subpacket::regular(SubpacketData::IssuerFingerprint(primary.fingerprint()))?,
        Subpacket::regular(SubpacketData::KeyFlags(keyflags))?,
    ];
    config.unhashed_subpackets = vec![Subpacket::regular(SubpacketData::IssuerKeyId(
        primary.legacy_key_id(),
    ))?];

    let pw = Password::empty();
    Ok(config.sign_subkey_binding(primary, primary.public_key(), &pw, sub_pub)?)
}

/// Assemble a v4 primary + encryption subkey into a self-signed
/// [`SignedSecretKey`], given already-constructed public/secret params for
/// each. The ONE assembly path for every key this crate creates — random
/// (`generate_rsa`/`generate_nistp`/`generate_ed25519`/`generate_pqc_hybrid`)
/// and seed-derived (`derive_ed25519`/`derive_p521`) alike — so packet
/// framing, self-signature and subkey binding are identical between them;
/// only the raw key bytes, the creation time, and whether a provenance
/// notation applies differ per caller.
///
/// Builds packets directly with rpgp's public packet-assembly API instead of
/// `SecretKeyParamsBuilder`/`SecretKeyParams::generate()`, which only knows
/// how to consume an RNG through one giant per-algorithm `match` (see the
/// module doc comment on the device stack budget — that `match`, with the
/// `draft-pqc` arms inlined, is what overflowed KeyOS's 256 KB process stack
/// on the random-keygen paths). Never clones `sub_pub_key`/`PublicParams`-
/// carrying values: the subkey binding signature is computed from a borrow
/// *before* the public subkey is moved into the secret subkey packet.
#[allow(clippy::too_many_arguments)]
fn assemble_key(
    primary_alg: pgp::crypto::public_key::PublicKeyAlgorithm,
    primary_public_params: PublicParams,
    primary_secret_params: PlainSecretParams,
    sub_alg: pgp::crypto::public_key::PublicKeyAlgorithm,
    sub_public_params: PublicParams,
    sub_secret_params: PlainSecretParams,
    name: &str,
    email: &str,
    created: Timestamp,
    provenance: Option<(&[u8; 4], u32, DerivedAlg)>,
) -> Result<SignedSecretKey, PgpError> {
    let primary_pub_inner =
        PubKeyInner::new(KeyVersion::V4, primary_alg, created, None, primary_public_params)?;
    let primary_pub_key = PublicKey::from_inner(primary_pub_inner)?;
    let primary_sec_key = SecretKey::new(primary_pub_key, SecretParams::Plain(primary_secret_params))?;

    let sub_pub_inner =
        PubKeyInner::new(KeyVersion::V4, sub_alg, created, None, sub_public_params)?;
    let sub_pub_key = PublicSubkey::from_inner(sub_pub_inner)?;

    let uid = UserId::from_str(Default::default(), format!("{name} <{email}>"))
        .map_err(|e| PgpError(format!("Invalid user ID: {e}")))?;

    let cert_sig = sign_primary_self_cert(&primary_sec_key, &uid, created, provenance)?;
    let subkey_sig = sign_subkey_binding(&primary_sec_key, &sub_pub_key, created)?;
    let sub_sec_key = SecretSubkey::new(sub_pub_key, SecretParams::Plain(sub_secret_params))?;

    let key = SignedSecretKey {
        primary_key: primary_sec_key,
        details: SignedKeyDetails {
            revocation_signatures: Vec::new(),
            direct_signatures: Vec::new(),
            users: vec![uid.into_signed(cert_sig)],
            user_attributes: Vec::new(),
        },
        public_subkeys: Vec::new(),
        secret_subkeys: vec![SignedSecretSubKey {
            key: sub_sec_key,
            signatures: vec![subkey_sig],
        }],
    };
    key.verify_bindings()?;
    Ok(key)
}

/// Apply S2K passphrase protection outside the deterministic derivation —
/// with the system RNG, exactly as the random-keygen paths do, so S2K salts
/// never consume derivation bytes and never affect the fingerprint.
fn apply_passphrase(
    key: SignedSecretKey,
    passphrase: Option<&str>,
) -> Result<SignedSecretKey, PgpError> {
    match passphrase {
        Some(pw) if !pw.is_empty() => {
            let mut sys_rng = thread_rng();
            let pw = Password::from(pw);
            let mut k = key;
            k.primary_key.set_password(&mut sys_rng, &pw)?;
            for sub in &mut k.secret_subkeys {
                sub.key.set_password(&mut sys_rng, &pw)?;
            }
            Ok(k)
        }
        _ => Ok(key),
    }
}

/// Deterministically derive an Ed25519 (sign+certify) key with a Cv25519
/// encryption subkey from a 32-byte imported-seed root and a key index.
///
/// Cross-platform contract (PLAN-openpgp-keys-import.md §2.3): the key
/// material is specified as raw bytes — an RFC 8032 Ed25519 seed and an
/// RFC 7748 X25519 scalar — not as "whatever rpgp's RNG-driven generator
/// does with a seeded stream" (the old scheme this replaced, reproducible
/// only by rpgp 0.20). Any OpenPGP library can reproduce this key from the
/// same `root` + `index`.
///
/// Same root + same index => byte-identical key material and fingerprint,
/// regardless of user ID or passphrase: the passphrase is applied after
/// construction with the system RNG so S2K salts never consume derivation
/// bytes, and the self-signatures use the fixed creation time too, so two
/// derivations of the same root+index produce byte-identical armor apart
/// from the S2K salt when a passphrase is set.
pub fn derive_ed25519(
    root: &[u8; 32],
    root_id: &[u8; 4],
    index: u32,
    name: &str,
    email: &str,
    passphrase: Option<&str>,
) -> Result<SignedSecretKey, PgpError> {
    let prk = key_prk(root);
    let sign_seed: [u8; 32] = expand(&prk, &hkdf_info(b"ed25519/", index, b"/sign"))?;
    let enc_key: [u8; 32] = expand(&prk, &hkdf_info(b"ed25519/", index, b"/encrypt"))?;

    // Primary: EdDSALegacy (alg 22), curve Ed25519. The RFC 8032 secret seed
    // is used directly — no clamping, ed25519-dalek hashes it internally.
    let ed_secret = ed25519::SecretKey::try_from_bytes(sign_seed, ed25519::Mode::EdDSALegacy)?;
    let primary_public_params = PublicParams::EdDSALegacy((&ed_secret).into());
    let primary_secret_params =
        PlainSecretParams::EdDSALegacy(eddsa_legacy::SecretKey::Ed25519(ed_secret));

    // Subkey: ECDH (alg 18), curve Curve25519 (legacy). `enc_key` is the
    // scalar in RFC 7748 native (little-endian) byte order, clamped per
    // RFC 7748. `Curve25519Legacy::try_from_bytes_rev` expects the legacy
    // MPI (reversed/big-endian) wire order and reverses it back to native
    // before storing — so we hand it the reverse of our clamped native
    // bytes, and the value it stores is exactly `clamp(enc_key)`.
    let clamped = clamp_x25519(enc_key);
    let mut wire = clamped;
    wire.reverse();
    let cv = ecdh::Curve25519Legacy::try_from_bytes_rev(&wire)?;
    let ecdh_secret = ecdh::SecretKey::Curve25519Legacy(cv);
    // KDF params (SHA-256 / AES-128) come from `ECCCurve::Curve25519Legacy`'s
    // own `hash_algo()`/`sym_algo()` via this conversion — the same values
    // rpgp's own generator would pick (pinned by
    // `derive_ed25519_ecdh_kdf_params_are_sha256_aes128` in tests/derive.rs).
    let sub_public_params = PublicParams::ECDH((&ecdh_secret).try_into()?);
    let sub_secret_params = PlainSecretParams::ECDH(ecdh_secret);

    let key = assemble_key(
        KeyType::Ed25519Legacy.to_alg(),
        primary_public_params,
        primary_secret_params,
        KeyType::ECDH(ECCCurve::Curve25519Legacy).to_alg(),
        sub_public_params,
        sub_secret_params,
        name,
        email,
        Timestamp::from_secs(DERIVED_KEY_CREATED_AT),
        Some((root_id, index, DerivedAlg::Ed25519)),
    )?;
    apply_passphrase(key, passphrase)
}

/// Deterministically derive a NIST P-521 (ECDSA sign+certify) key with a
/// P-521 ECDH encryption subkey from the imported-seed root and a key index.
///
/// A deliberate SIBLING of [`derive_ed25519`], not a refactor of it: this one
/// duplicates the shape with its own HKDF info prefix (`p521/`). The prefix
/// domain-separates the two streams — the same root + index yields
/// independent Ed25519 and P-521 identities.
///
/// Reproducibility rests on the raw-bytes contract in
/// PLAN-openpgp-keys-import.md §2.3, not on any particular rpgp version: any
/// OpenPGP library that can build a P-521 key from an SEC1 scalar can
/// reproduce this. The pinned-fingerprint tests in tests/derive.rs gate any
/// accidental drift.
pub fn derive_p521(
    root: &[u8; 32],
    root_id: &[u8; 4],
    index: u32,
    name: &str,
    email: &str,
    passphrase: Option<&str>,
) -> Result<SignedSecretKey, PgpError> {
    let prk = key_prk(root);
    let sign_raw: [u8; 80] = expand(&prk, &hkdf_info(b"p521/", index, b"/sign"))?;
    let enc_raw: [u8; 80] = expand(&prk, &hkdf_info(b"p521/", index, b"/encrypt"))?;

    // Primary: ECDSA (alg 19), curve P-521. `sign_raw` is reduced into a
    // valid scalar per FIPS 186-4 B.4.1 (see `p521_scalar_from_raw`).
    let sign_key = p521_secret_key(sign_raw)?;
    let ecdsa_secret = ecdsa::SecretKey::P521(sign_key);
    let primary_public_params = PublicParams::ECDSA((&ecdsa_secret).try_into()?);
    let primary_secret_params = PlainSecretParams::ECDSA(ecdsa_secret);

    // Subkey: ECDH (alg 18), curve P-521.
    let enc_key = p521_secret_key(enc_raw)?;
    let ecdh_secret = ecdh::SecretKey::P521 { secret: enc_key };
    // KDF params (SHA-512 / AES-256) come from `ECCCurve::P521`'s own
    // `hash_algo()`/`sym_algo()` via this conversion — pinned by
    // `derive_p521_ecdh_kdf_params_are_sha512_aes256` in tests/derive.rs.
    let sub_public_params = PublicParams::ECDH((&ecdh_secret).try_into()?);
    let sub_secret_params = PlainSecretParams::ECDH(ecdh_secret);

    let key = assemble_key(
        KeyType::ECDSA(ECCCurve::P521).to_alg(),
        primary_public_params,
        primary_secret_params,
        KeyType::ECDH(ECCCurve::P521).to_alg(),
        sub_public_params,
        sub_secret_params,
        name,
        email,
        Timestamp::from_secs(DERIVED_KEY_CREATED_AT),
        Some((root_id, index, DerivedAlg::P521)),
    )?;
    apply_passphrase(key, passphrase)
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
    key: SignedSecretKey,
    old: &str,
    new: Option<&str>,
) -> Result<SignedSecretKey, PgpError> {
    let old_pw = to_password(old);
    // Takes the key BY VALUE: see the "Editing takes the key by value" note.
    let mut k = key;
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

/// Pick the signing component key — the primary when its newest self-cert
/// carries the sign flag (all keys this app generates do), otherwise the
/// newest signing-capable secret subkey — and unlock it so a bad passphrase
/// surfaces as WRONG_PASSPHRASE instead of an opaque signing error.
fn select_signer<'a>(
    key: &'a SignedSecretKey,
    pw: &Password,
) -> Result<Box<&'a dyn SigningKey>, PgpError> {
    let fpr = key.primary_key.fingerprint();
    let key_id = key.primary_key.legacy_key_id();
    let primary_signs = latest_self_cert(&key.details.users, &fpr, &key_id)
        .map_or(true, |sig| sig.key_flags().sign());

    if primary_signs {
        key.primary_key
            .unlock(pw, |_, _| Ok(()))
            .map_err(wrong_pw)?
            .map_err(|e| PgpError(e.to_string()))?;
        Ok(Box::new(&key.primary_key))
    } else {
        let sub = key
            .secret_subkeys
            .iter()
            .filter(|s| s.signatures.first().is_some_and(|b| b.key_flags().sign()))
            .max_by_key(|s| s.key.created_at().as_secs())
            .ok_or_else(|| PgpError("Key has no signing-capable secret key".into()))?;
        sub.key
            .unlock(pw, |_, _| Ok(()))
            .map_err(wrong_pw)?
            .map_err(|e| PgpError(e.to_string()))?;
        Ok(Box::new(&sub.key))
    }
}

fn make_detached_signature(
    key: &SignedSecretKey,
    pass: &str,
    data: &[u8],
) -> Result<DetachedSignature, PgpError> {
    let pw = to_password(pass);
    let signer = select_signer(key, &pw)?;
    let hash = signer.hash_alg();
    Ok(DetachedSignature::sign_binary_data(thread_rng(), &signer, &pw, hash, data)?)
}

// ---------------------------------------------------------------------------
// Encryption / decryption
// ---------------------------------------------------------------------------

/// Encrypt `data` to `recipient`'s encryption subkey as a binary OpenPGP
/// message (AES-256, SEIPDv1, uncompressed) — what `gpg -e` produces and
/// `gpg -d` reads. Needs only public key material.
///
/// `sign_with: Some((key, pass))` additionally signs inside the encrypted
/// container (one-pass signature, like `gpg -se`).
pub fn encrypt_bytes(
    recipient: &PgpKey,
    file_name: &str,
    data: Vec<u8>,
    sign_with: Option<(&SignedSecretKey, &str)>,
) -> Result<Vec<u8>, PgpError> {
    let owned_pk;
    let pk: &SignedPublicKey = match recipient {
        PgpKey::Public(p) => p,
        PgpKey::Secret(s) => {
            owned_pk = s.to_public_key();
            &owned_pk
        }
    };
    // Encrypt to the encryption-capable subkey. Passing the whole
    // SignedPublicKey would encrypt to the sign/certify-only PRIMARY key —
    // producing a message the recipient can never decrypt.
    let enc_key = pk
        .public_subkeys
        .iter()
        .find(|s| s.algorithm().can_encrypt())
        .ok_or_else(|| PgpError("Key has no encryption subkey".into()))?;

    let mut rng = thread_rng();
    let mut builder = MessageBuilder::from_bytes(file_name.to_string(), data)
        .seipd_v1(&mut rng, SymmetricKeyAlgorithm::AES256);
    // Compress before encrypting (ZLIB/DEFLATE), matching gpg's default —
    // smaller output, and our decrypt already handles compressed messages.
    builder.compression(CompressionAlgorithm::ZLIB);
    builder.encrypt_to_key(&mut rng, enc_key)?;
    if let Some((sk, pass)) = sign_with {
        let pw = to_password(pass);
        let signer = select_signer(sk, &pw)?;
        let hash = signer.hash_alg();
        builder.sign(*signer, pw, hash);
    }
    Ok(builder.to_vec(&mut rng)?)
}

/// Decrypt a binary or armored OpenPGP message with the key's encryption
/// subkey. Wrong passphrase surfaces as WRONG_PASSPHRASE; malformed input
/// returns an error instead of panicking.
pub fn decrypt_bytes(
    key: &SignedSecretKey,
    pass: &str,
    data: Vec<u8>,
) -> Result<Vec<u8>, PgpError> {
    let pw = to_password(pass);

    // Pre-flight unlock: Message::decrypt reports MissingKey for both a
    // wrong passphrase and a message for someone else, so distinguish the
    // passphrase failure here (primary fallback covers imported
    // encrypt-capable primaries with no subkey).
    match key
        .secret_subkeys
        .iter()
        .find(|s| s.key.algorithm().can_encrypt())
    {
        Some(sub) => sub.key.unlock(&pw, |_, _| Ok(())),
        None => key.primary_key.unlock(&pw, |_, _| Ok(())),
    }
    .map_err(wrong_pw)?
    .map_err(|e| PgpError(e.to_string()))?;

    catch_unwind(AssertUnwindSafe(move || -> Result<Vec<u8>, PgpError> {
        // from_reader auto-detects binary vs armored input.
        let (msg, _headers) = Message::from_reader(Cursor::new(data))?;
        let mut msg = msg.decrypt(&pw, key)?;
        // gpg compresses by default (ZIP/ZLIB — flate2 is always built).
        while msg.is_compressed() {
            msg = msg.decompress()?;
        }
        // Reads the literal data through a Signed layer transparently.
        msg.as_data_vec()
            .map_err(|e| PgpError(format!("Could not read decrypted data: {e}")))
    }))
    .map_err(|_| PgpError("Malformed OpenPGP message (parser crashed)".into()))?
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
        // Carry over any notations (in practice: the `derived@byteapps.com`
        // provenance notation on a derived key) so re-signing paths — expiry
        // changes, adding a user ID — never silently drop it. See
        // PLAN-openpgp-keys-import.md §6.
        for notation in t.notations() {
            hashed.push(Subpacket::regular(SubpacketData::Notation(
                notation.clone(),
            ))?);
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
    key: SignedSecretKey,
    pass: &str,
    days_from_now: Option<u32>,
    now_epoch: i64,
) -> Result<SignedSecretKey, PgpError> {
    let pw = to_password(pass);
    check_passphrase(&key, pass)?;

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

    // Phase 1: build every replacement self-signature against a BORROW, so
    // nothing needs a second copy of the key.
    let mut fresh = Vec::with_capacity(key.details.users.len());
    for (i, user) in key.details.users.iter().enumerate() {
        fresh.push(resign_user_id(
            &key,
            &pw,
            &user.id,
            template.as_ref(),
            expiry_secs_from_creation,
            i == 0,
        )?);
    }

    // Phase 2: apply them in place, consuming the key we were handed.
    let mut k = key;
    for (user, sig) in k.details.users.iter_mut().zip(fresh) {
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
    key: SignedSecretKey,
    pass: &str,
    name: &str,
    email: &str,
) -> Result<SignedSecretKey, PgpError> {
    let pw = to_password(pass);
    check_passphrase(&key, pass)?;

    let uid = UserId::from_str(Default::default(), format!("{name} <{email}>"))
        .map_err(|e| PgpError(format!("Invalid user ID: {e}")))?;

    let fpr = key.primary_key.fingerprint();
    let key_id = key.primary_key.legacy_key_id();
    let template = latest_self_cert(&key.details.users, &fpr, &key_id).cloned();
    // Carry the current expiration over so gpg computes a consistent expiry
    // across all user IDs.
    let expiry = template.as_ref().and_then(|t| t.key_expiration_time());

    let sig = resign_user_id(
        &key,
        &pw,
        &uid,
        template.as_ref(),
        expiry.map(|d| d.as_secs()),
        false,
    )?;

    let mut k = key;
    k.details.users.push(uid.into_signed(sig));
    k.verify_bindings()?;
    Ok(k)
}

/// Remove the user ID at `index`. Refuses to remove the last one.
pub fn remove_user_id(key: SignedSecretKey, index: usize) -> Result<SignedSecretKey, PgpError> {
    if key.details.users.len() <= 1 {
        return Err(PgpError("Cannot remove the last user ID".into()));
    }
    if index >= key.details.users.len() {
        return Err(PgpError("No such user ID".into()));
    }
    let mut k = key;
    k.details.users.remove(index);
    k.verify_bindings()?;
    Ok(k)
}
