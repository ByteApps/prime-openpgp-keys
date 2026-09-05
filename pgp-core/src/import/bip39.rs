//! Canonical copy of `graffito/notes-core/src/bip39.rs` — edit there and
//! re-copy. Adapted only in its error type (`Error` -> `PgpError`) and
//! extended with `mnemonic_to_entropy` (checksum-validated decode, needed
//! for import — notes-core only ever generates, never imports) and
//! `suggest` (UI prefix-autocomplete helper).
//!
//! BIP-39: entropy → English mnemonic, mnemonic → 64-byte seed.
//! English-only, which keeps normalization trivial: the wordlist is pure
//! ASCII, so NFKD is a no-op on it.

use pbkdf2::pbkdf2_hmac;
use sha2::{Digest, Sha256, Sha512};

use crate::PgpError;

/// Canonical English wordlist, checked in verbatim
/// (sha256 2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda).
pub const WORDS: &str = include_str!("english.txt");

pub fn wordlist() -> Vec<&'static str> {
    WORDS.lines().collect()
}

/// 11-bit wordlist indices for the given entropy (16/24/32 bytes).
pub fn entropy_to_indices(entropy: &[u8]) -> Result<Vec<u16>, PgpError> {
    if !matches!(entropy.len(), 16 | 24 | 32) {
        return Err(PgpError("bad entropy length".into()));
    }
    let checksum_bits = entropy.len() * 8 / 32;
    let checksum = Sha256::digest(entropy)[0] >> (8 - checksum_bits);

    // Accumulate entropy || checksum bits, emitting an index every 11 bits.
    let mut indices = Vec::with_capacity((entropy.len() * 8 + checksum_bits) / 11);
    let mut acc: u32 = 0;
    let mut bits = 0;
    let mut push_bits = |acc: &mut u32, bits: &mut usize, n: usize, value: u32| {
        *acc = (*acc << n) | value;
        *bits += n;
        while *bits >= 11 {
            indices.push(((*acc >> (*bits - 11)) & 0x7FF) as u16);
            *bits -= 11;
        }
    };
    for byte in entropy {
        push_bits(&mut acc, &mut bits, 8, *byte as u32);
    }
    push_bits(&mut acc, &mut bits, checksum_bits, checksum as u32);
    Ok(indices)
}

pub fn entropy_to_mnemonic(entropy: &[u8]) -> Result<String, PgpError> {
    let list = wordlist();
    let words: Vec<&str> =
        entropy_to_indices(entropy)?.into_iter().map(|i| list[i as usize]).collect();
    Ok(words.join(" "))
}

/// PBKDF2-HMAC-SHA512, 2048 rounds, salt `"mnemonic" + passphrase`.
pub fn mnemonic_to_seed(mnemonic: &str, passphrase: &str) -> [u8; 64] {
    let salt = format!("mnemonic{passphrase}");
    let mut seed = [0u8; 64];
    pbkdf2_hmac::<Sha512>(mnemonic.as_bytes(), salt.as_bytes(), 2048, &mut seed);
    seed
}

/// Inverse of [`entropy_to_mnemonic`], with checksum verification: a
/// space-separated mnemonic (already normalized: lowercase, single
/// spaces, no leading/trailing whitespace) of exactly 12 or 24 words ->
/// its 16/32-byte entropy, or an error naming the first unknown word or
/// reporting a checksum mismatch.
///
/// Only 12/24 words are accepted here (this app's contract, per the
/// plan — Sal, 2026-09-04); the underlying bit-packing in
/// [`entropy_to_indices`]/this function's own accumulation supports the
/// full BIP-39 12/24 -> 16/32-byte mapping, not the 15/18/21-word forms.
pub fn mnemonic_to_entropy(mnemonic: &str) -> Result<Vec<u8>, PgpError> {
    let words: Vec<&str> = mnemonic.split(' ').filter(|w| !w.is_empty()).collect();
    let count = words.len();
    if !matches!(count, 12 | 24) {
        return Err(PgpError("Enter 12 or 24 words".into()));
    }

    let list = wordlist();
    let mut indices = Vec::with_capacity(count);
    for w in &words {
        let idx = list
            .binary_search(w)
            .map_err(|_| PgpError(format!("Unknown word: {w}")))?;
        indices.push(idx as u16);
    }

    let entropy_len = if count == 12 { 16 } else { 32 };

    // Pack the 11-bit indices into a bit stream, MSB-first, then take the
    // leading `entropy_len` bytes as the candidate entropy.
    let mut acc: u32 = 0;
    let mut bits: usize = 0;
    let mut stream = Vec::with_capacity(entropy_len + 1);
    for idx in &indices {
        acc = (acc << 11) | (*idx as u32);
        bits += 11;
        while bits >= 8 {
            bits -= 8;
            stream.push(((acc >> bits) & 0xFF) as u8);
        }
    }
    if bits > 0 {
        stream.push(((acc << (8 - bits)) & 0xFF) as u8);
    }
    let entropy = stream[..entropy_len].to_vec();

    // Verify the checksum by re-deriving the indices from the candidate
    // entropy and comparing — reuses the (already-correct) generation
    // path instead of re-deriving the checksum-bit-slicing by hand.
    if entropy_to_indices(&entropy)? != indices {
        return Err(PgpError("Checksum does not match — check the words".into()));
    }

    Ok(entropy)
}

/// Prefix-autocomplete over the wordlist, for the UI's on-screen keyboard.
/// The list is alphabetically sorted, so this returns matches in that
/// order.
pub fn suggest(prefix: &str, max: usize) -> Vec<&'static str> {
    let prefix = prefix.to_lowercase();
    wordlist()
        .into_iter()
        .filter(|w| w.starts_with(prefix.as_str()))
        .take(max)
        .collect()
}
