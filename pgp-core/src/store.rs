//! Seal/open the imported-seed root at rest (PLAN-openpgp-keys-import.md §4).
//!
//! Every function here is a pure function of the sealing seed (the device's
//! `GetAppSeed` output) and byte slices — this module never touches the
//! filesystem. The app layer is responsible for reading/writing
//! `Location::AppData` `/imported_key` and for read-back verification
//! after a write (no `FlushFs` for third-party apps — KeyOS#9).
//!
//! # Blob layout (FROZEN once shipped)
//!
//! ```text
//! magic      b"OPGK"                      4
//! version    0x01                         1
//! words      12 | 24                      1
//! pass_used  0 | 1                        1
//! root_id    [u8; 4]                      4   (cleartext, shown in the UI)
//! nonce      [u8; 24]
//! ct || tag  XChaCha20-Poly1305(root || xfp)   36 + 16 = 52
//! ------------------------------------------------------
//! total                                        87 bytes
//! ```
//!
//! The 36-byte plaintext is `root[32] || xfp[4]` — the BIP-32 master
//! fingerprint of the imported seed rides *inside* the encryption (not the
//! cleartext header) because it links the seed to a bitcoin wallet.
//!
//! ```text
//! sealing key = HKDF-SHA256:
//!   PRK = Extract(salt = "com.byteapps.openpgp-keys/store/v1", IKM = app_seed[32])
//!   key = Expand(PRK, "root-seal", 32)
//! AAD = the 11 header bytes (magic..root_id) exactly as laid out above
//! ```
//!
//! Nonces are drawn from `rand::rngs::OsRng` (rand 0.8 -> rand_core 0.6 ->
//! getrandom 0.2, the line the workspace's vendored TRNG patch covers).
//! `chacha20poly1305`'s own `getrandom`/`rand_core` features are
//! deliberately OFF (see Cargo.toml) so this module cannot add a getrandom
//! 0.3/0.4 edge to the dependency graph.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::PgpError;

const MAGIC: &[u8; 4] = b"OPGK";
const VERSION: u8 = 0x01;

/// `HKDF-Extract` salt for the store-sealing key. Reverse-DNS naming
/// matches `com.byteapps.graffito` (PLAN-openpgp-keys-import.md §2.2).
const STORE_SALT: &[u8] = b"com.byteapps.openpgp-keys/store/v1";
const STORE_INFO: &[u8] = b"root-seal";

/// `magic(4) || version(1) || words(1) || pass_used(1) || root_id(4)`.
const HEADER_LEN: usize = 11;
const NONCE_LEN: usize = 24;
/// `root(32) || xfp(4)`, sealed as one AEAD plaintext.
const PLAINTEXT_LEN: usize = 36;
const TAG_LEN: usize = 16;

/// Total sealed-blob length: header + nonce + ciphertext + tag.
pub const BLOB_LEN: usize = HEADER_LEN + NONCE_LEN + PLAINTEXT_LEN + TAG_LEN;

/// Cleartext header metadata, readable without the sealing key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RootMeta {
    pub words: u8,
    pub pass_used: bool,
    pub root_id: [u8; 4],
}

/// The root plus the BIP-32 master fingerprint it was derived alongside,
/// both zeroized on drop.
///
/// `Debug` is derived only so `Result<(RootMeta, UnsealedRoot), _>::unwrap_err()`
/// works in tests — `Zeroizing<T>`'s `Debug` impl prints the same bytes `T`
/// would, so nothing here is redacted; the app layer must never log this
/// value.
#[derive(Debug)]
pub struct UnsealedRoot {
    pub root: Zeroizing<[u8; 32]>,
    pub xfp: Zeroizing<[u8; 4]>,
}

fn validate_words(words: u8) -> Result<(), PgpError> {
    if words != 12 && words != 24 {
        return Err(PgpError(format!(
            "Word count must be 12 or 24, got {words}"
        )));
    }
    Ok(())
}

fn sealing_key(app_seed: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let prk = Hkdf::<Sha256>::new(Some(STORE_SALT), app_seed);
    let mut key = Zeroizing::new([0u8; 32]);
    // 32 <= 255 * HashLen(SHA-256) always holds, so `expand` cannot fail here.
    prk.expand(STORE_INFO, key.as_mut())
        .expect("HKDF-Expand to 32 bytes cannot fail");
    key
}

fn build_header(meta: &RootMeta) -> [u8; HEADER_LEN] {
    let mut header = [0u8; HEADER_LEN];
    header[0..4].copy_from_slice(MAGIC);
    header[4] = VERSION;
    header[5] = meta.words;
    header[6] = meta.pass_used as u8;
    header[7..11].copy_from_slice(&meta.root_id);
    header
}

/// Seal `root` (and its BIP-32 master fingerprint `xfp`) under `app_seed`
/// with a fresh OS-random nonce. Rejects `meta.words` outside `{12, 24}`.
pub fn seal_root(
    app_seed: &[u8; 32],
    meta: &RootMeta,
    root: &[u8; 32],
    xfp: &[u8; 4],
) -> Result<Vec<u8>, PgpError> {
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    seal_root_with_nonce(app_seed, meta, root, xfp, &nonce)
}

/// Same as [`seal_root`] but with an explicit nonce. Exposed only for the
/// pinned-vector test (FROZEN format contract) — production callers use
/// [`seal_root`], which draws a fresh nonce from the OS CSPRNG.
#[doc(hidden)]
pub fn seal_root_with_nonce(
    app_seed: &[u8; 32],
    meta: &RootMeta,
    root: &[u8; 32],
    xfp: &[u8; 4],
    nonce: &[u8; NONCE_LEN],
) -> Result<Vec<u8>, PgpError> {
    validate_words(meta.words)?;

    let header = build_header(meta);
    let key = sealing_key(app_seed);
    let cipher = XChaCha20Poly1305::new((&*key).into());

    let mut plaintext = Zeroizing::new([0u8; PLAINTEXT_LEN]);
    plaintext[0..32].copy_from_slice(root);
    plaintext[32..36].copy_from_slice(xfp);

    let ct = cipher
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: plaintext.as_ref(),
                aad: &header,
            },
        )
        .map_err(|_| PgpError("Failed to seal imported seed root".into()))?;

    let mut blob = Vec::with_capacity(BLOB_LEN);
    blob.extend_from_slice(&header);
    blob.extend_from_slice(nonce);
    blob.extend_from_slice(&ct);
    debug_assert_eq!(blob.len(), BLOB_LEN);
    Ok(blob)
}

/// Read the cleartext header of a sealed blob without needing the sealing
/// key — lets the UI show the root ID before/without unlocking.
pub fn peek_meta(blob: &[u8]) -> Result<RootMeta, PgpError> {
    if blob.len() != BLOB_LEN {
        return Err(PgpError(format!(
            "Stored seed blob has the wrong length: expected {BLOB_LEN} bytes, got {}",
            blob.len()
        )));
    }
    if &blob[0..4] != MAGIC {
        return Err(PgpError("Not a stored imported-seed root (bad magic)".into()));
    }
    let version = blob[4];
    if version != VERSION {
        return Err(PgpError(format!(
            "Unsupported stored-seed format version: {version}"
        )));
    }
    let words = blob[5];
    validate_words(words)?;
    let pass_used_byte = blob[6];
    if pass_used_byte != 0 && pass_used_byte != 1 {
        return Err(PgpError(format!(
            "Stored seed has an invalid passphrase-used flag: {pass_used_byte}"
        )));
    }
    let mut root_id = [0u8; 4];
    root_id.copy_from_slice(&blob[7..11]);

    Ok(RootMeta {
        words,
        pass_used: pass_used_byte == 1,
        root_id,
    })
}

/// Open a sealed blob, returning the header metadata plus the root and its
/// BIP-32 master fingerprint (both zeroized on drop). A failed AEAD open —
/// wrong `app_seed`, or any tampering with the header/nonce/ciphertext/tag —
/// returns a single message: "Stored seed cannot be unlocked with this
/// device's seed".
pub fn open_root(app_seed: &[u8; 32], blob: &[u8]) -> Result<(RootMeta, UnsealedRoot), PgpError> {
    let meta = peek_meta(blob)?;

    let header = &blob[0..HEADER_LEN];
    let nonce = &blob[HEADER_LEN..HEADER_LEN + NONCE_LEN];
    let ct = &blob[HEADER_LEN + NONCE_LEN..];

    let key = sealing_key(app_seed);
    let cipher = XChaCha20Poly1305::new((&*key).into());

    let plaintext = Zeroizing::new(
        cipher
            .decrypt(XNonce::from_slice(nonce), Payload { msg: ct, aad: header })
            .map_err(|_| {
                PgpError("Stored seed cannot be unlocked with this device's seed".into())
            })?,
    );
    debug_assert_eq!(plaintext.len(), PLAINTEXT_LEN);

    let mut root = Zeroizing::new([0u8; 32]);
    root.copy_from_slice(&plaintext[0..32]);
    let mut xfp = Zeroizing::new([0u8; 4]);
    xfp.copy_from_slice(&plaintext[32..36]);

    Ok((meta, UnsealedRoot { root, xfp }))
}
