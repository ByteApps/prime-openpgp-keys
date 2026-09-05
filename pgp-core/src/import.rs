//! Imported-seed root derivation — PLAN-openpgp-keys-import.md §2.
//!
//! Cross-platform contract: a BIP-39 mnemonic (12 or 24 English words)
//! plus an optional BIP-39 passphrase derive a 32-byte `root`, the only
//! secret this app persists (sealed at rest, see `store` — U3). Every
//! string, salt, and byte length below is FROZEN once shipped: a future
//! desktop/mobile OpenPGP Keys app must reproduce the same root (and
//! therefore the same derived keys, §2.3) from the same words +
//! passphrase.
//!
//! ```text
//! seed64  = PBKDF2-HMAC-SHA512(password = mnemonic, salt = "mnemonic" || passphrase, 2048, 64)
//! PRK     = HKDF-Extract(salt = ROOT_SALT, IKM = seed64)
//! root    = HKDF-Expand(PRK, info = "root",    L = 32)
//! root_id = HKDF-Expand(PRK, info = "root-id", L = 4)
//! ```
//!
//! `xfp` is a *separate*, standard BIP-32 computation over the same
//! `seed64` (`HMAC-SHA512("Bitcoin seed", seed64)` -> master privkey ->
//! compressed secp256k1 pubkey -> `RIPEMD160(SHA256(pubkey))[..4]`) —
//! the same fingerprint a hardware wallet shows for this seed +
//! passphrase, so the UI can offer it as a typo/mismatch check against
//! an external device without either side learning anything new about
//! the other's key material (it is derived from `seed64`, never from
//! `root`).

pub mod bip39;

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::elliptic_curve::PrimeField;
use k256::{ProjectivePoint, Scalar};
use pbkdf2::pbkdf2_hmac;
use ripemd::Ripemd160;
use sha2::{Digest, Sha256, Sha512};
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

use crate::PgpError;

/// HKDF-Extract salt for the root (§2.2). Reverse-DNS-styled to match
/// `com.byteapps.graffito`; deliberately excludes the Prime app-id since
/// a desktop build has none and the value must be identical everywhere.
const ROOT_SALT: &[u8] = b"com.byteapps.openpgp-keys/root/v1";

/// Maximum passphrase length in **characters** (not bytes) — matches the
/// reference hardware signer's BIP-39 passphrase cap, so a phrase that
/// works there works here.
const MAX_PASSPHRASE_CHARS: usize = 100;

/// The imported-seed root and its public metadata.
pub struct Root {
    /// The only secret this app persists (sealed at rest — see `store`).
    pub root: Zeroizing<[u8; 32]>,
    /// Public: a wallet-fingerprint-style check that two imports agree
    /// on the same words + passphrase.
    pub root_id: [u8; 4],
    /// 12 or 24 — the mnemonic length used.
    pub words: u8,
    /// Whether a non-empty passphrase was used.
    pub pass_used: bool,
    /// BIP-32 master fingerprint of the same seed64 — the value a
    /// hardware wallet would show for this seed + passphrase. Public.
    pub xfp: [u8; 4],
}

impl Root {
    /// [`Self::root_id`] as the 8 upper-hex chars shown in the UI.
    pub fn root_id_hex(&self) -> String {
        self.root_id.iter().map(|b| format!("{b:02X}")).collect()
    }

    /// [`Self::xfp`] as the conventional 8 lowercase hex chars (the
    /// wallet-display convention, distinct from `root_id_hex`'s
    /// upper-hex to keep the two visually unmistakable in the UI).
    pub fn xfp_hex(&self) -> String {
        self.xfp.iter().map(|b| format!("{b:02x}")).collect()
    }
}

fn nfkd(raw: &str) -> String {
    raw.nfkd().collect()
}

/// NFKD-normalize, lowercase, and collapse all whitespace runs (leading,
/// trailing, and internal) to single ASCII spaces.
fn collapse(raw: &str) -> String {
    nfkd(raw).to_lowercase().split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Normalize and validate a mnemonic: NFKD, lowercase, single-spaced,
/// exactly 12 or 24 words, every word in the English BIP-39 list, valid
/// checksum. The returned string is the exact byte sequence fed to
/// PBKDF2 as the password.
pub fn normalize_mnemonic(raw: &str) -> Result<Zeroizing<String>, PgpError> {
    let normalized = collapse(raw);
    let words: Vec<&str> = normalized.split(' ').filter(|w| !w.is_empty()).collect();
    if !matches!(words.len(), 12 | 24) {
        return Err(PgpError("Enter 12 or 24 words".into()));
    }
    let list = bip39::wordlist();
    for w in &words {
        if list.binary_search(w).is_err() {
            return Err(PgpError(format!("Unknown word: {w}")));
        }
    }
    // Word count and membership are already confirmed above, so the only
    // way `mnemonic_to_entropy` can still fail here is a bad checksum.
    bip39::mnemonic_to_entropy(&normalized).map_err(|_| {
        PgpError("Checksum does not match — check the words".into())
    })?;
    Ok(Zeroizing::new(normalized))
}

/// Normalize and validate a passphrase: NFKD, at most 100 **characters**.
/// Empty is fine (== no passphrase). Case and whitespace are preserved —
/// unlike the mnemonic, a passphrase is an arbitrary user secret.
pub fn normalize_passphrase(raw: &str) -> Result<Zeroizing<String>, PgpError> {
    let normalized = nfkd(raw);
    if normalized.chars().count() > MAX_PASSPHRASE_CHARS {
        return Err(PgpError(format!(
            "Passphrase must be {MAX_PASSPHRASE_CHARS} characters or fewer"
        )));
    }
    Ok(Zeroizing::new(normalized))
}

/// `PBKDF2-HMAC-SHA512(password = normalized_mnemonic, salt = "mnemonic"
/// || normalized_passphrase, rounds = 2048, dkLen = 64)` — plain BIP-39.
/// Exposed (not just internal to [`derive_root`]) so tests and the
/// reference-signer cross-check (plan §7) can pin it independently of
/// the root/root_id/xfp built on top of it.
pub fn mnemonic_to_seed64(
    normalized_mnemonic: &str,
    normalized_passphrase: &str,
) -> Zeroizing<[u8; 64]> {
    let mut salt = Zeroizing::new(String::from("mnemonic"));
    salt.push_str(normalized_passphrase);
    let mut seed = Zeroizing::new([0u8; 64]);
    pbkdf2_hmac::<Sha512>(normalized_mnemonic.as_bytes(), salt.as_bytes(), 2048, seed.as_mut());
    seed
}

fn hmac_sha512(key: &[u8], msg: &[u8]) -> Zeroizing<[u8; 64]> {
    let mut mac = Hmac::<Sha512>::new_from_slice(key).expect("hmac accepts any key length");
    mac.update(msg);
    Zeroizing::new(mac.finalize().into_bytes().into())
}

/// BIP-32 master-key fingerprint (`xfp`) of `seed64`: the same value a
/// hardware wallet displays for this seed + passphrase. `seed64` is
/// *shared* input with the OpenPGP root derivation but the two paths are
/// otherwise independent — this never touches `ROOT_SALT`/HKDF, and the
/// root derivation never touches secp256k1.
fn xfp_from_seed64(seed64: &[u8; 64]) -> Result<[u8; 4], PgpError> {
    let i = hmac_sha512(b"Bitcoin seed", seed64);
    let (il, _ir) = i.split_at(32);
    let key: [u8; 32] = il.try_into().expect("hmac-sha512 output is 64 bytes");
    let scalar = Option::<Scalar>::from(Scalar::from_repr(key.into()))
        .ok_or_else(|| PgpError("seed produced an out-of-range master key".into()))?;
    if bool::from(scalar.is_zero()) {
        return Err(PgpError("seed produced a zero master key".into()));
    }
    let point = (ProjectivePoint::GENERATOR * scalar).to_affine();
    let pubkey: [u8; 33] = point
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .expect("compressed SEC1 point is 33 bytes");
    let h160 = Ripemd160::digest(Sha256::digest(pubkey));
    Ok(h160[..4].try_into().expect("ripemd160 output is >= 4 bytes"))
}

/// Derive the imported-seed [`Root`] (and its `xfp`) from raw user input.
/// Both the mnemonic and the passphrase are normalized and validated
/// first (see [`normalize_mnemonic`]/[`normalize_passphrase`]); any
/// rejection there is returned as-is.
pub fn derive_root(mnemonic_raw: &str, passphrase_raw: &str) -> Result<Root, PgpError> {
    let mnemonic = normalize_mnemonic(mnemonic_raw)?;
    let passphrase = normalize_passphrase(passphrase_raw)?;

    let words = mnemonic.split(' ').filter(|w| !w.is_empty()).count() as u8;
    let pass_used = !passphrase.is_empty();

    let seed64 = mnemonic_to_seed64(&mnemonic, &passphrase);

    // `Hkdf::new` computes the Extract-step PRK internally and never
    // exposes it, so there is no raw PRK for us to zeroize by hand; `hk`
    // (which owns it) is dropped at the end of this scope regardless.
    let hk = Hkdf::<Sha256>::new(Some(ROOT_SALT), seed64.as_ref());

    let mut root = Zeroizing::new([0u8; 32]);
    hk.expand(b"root", root.as_mut()).expect("32 <= 255*32");
    let mut root_id = [0u8; 4];
    hk.expand(b"root-id", &mut root_id).expect("4 <= 255*32");

    let xfp = xfp_from_seed64(&seed64)?;

    Ok(Root { root, root_id, words, pass_used, xfp })
}
