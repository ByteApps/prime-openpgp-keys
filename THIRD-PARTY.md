# Third-party libraries

Direct dependencies of this app and its `pgp-core` library. The complete transitive list (with exact versions) is pinned in [`Cargo.lock`](Cargo.lock).

## Rust crates

| Library | Version | License | Used for |
|---|---|---|---|
| [pgp](https://github.com/rpgp/rpgp) (rpgp) | 0.20.0 (pinned) | MIT OR Apache-2.0 | Pure-Rust OpenPGP: parsing, key generation, signing, encryption. The `draft-pqc` feature is enabled for the RFC 9980 post-quantum hybrid, pulling [ml-kem](https://crates.io/crates/ml-kem), [ml-dsa](https://crates.io/crates/ml-dsa) and [slh-dsa](https://crates.io/crates/slh-dsa) (RustCrypto, Apache-2.0 OR MIT) into the graph |
| [rsa](https://crates.io/crates/rsa) | 0.9 | MIT OR Apache-2.0 | RSA key introspection (modulus sizes; same copy rpgp uses) |
| [hkdf](https://crates.io/crates/hkdf) | 0.12 | MIT OR Apache-2.0 | Imported-seed derivation: HKDF-SHA256 expansion of the BIP-39 seed into the root and per-key material |
| [sha2](https://crates.io/crates/sha2) | 0.10 | MIT OR Apache-2.0 | SHA-256 for derivation |
| [rand](https://crates.io/crates/rand) | 0.8 | MIT OR Apache-2.0 | RNG plumbing for random key generation and the sealed-store nonce |
| [pbkdf2](https://crates.io/crates/pbkdf2) | 0.12.2 | MIT OR Apache-2.0 | BIP-39 mnemonic → seed (PBKDF2-HMAC-SHA512, 2048 rounds) |
| [unicode-normalization](https://crates.io/crates/unicode-normalization) | 0.1.25 | MIT OR Apache-2.0 | NFKD normalization of the imported mnemonic and passphrase |
| [zeroize](https://crates.io/crates/zeroize) | 1.9.0 | Apache-2.0 OR MIT | Zeroizing the mnemonic, passphrase, seed, and root intermediates on drop |
| [k256](https://crates.io/crates/k256) | 0.13.4 | Apache-2.0 OR MIT | BIP-32 master-key fingerprint (`xfp`) of the imported seed — secp256k1 point arithmetic only, no wallet functionality |
| [hmac](https://crates.io/crates/hmac) | 0.12.1 | MIT OR Apache-2.0 | HMAC-SHA512 for BIP-39 seed → BIP-32 master key, and the store's HKDF |
| [ripemd](https://crates.io/crates/ripemd) | 0.1.3 | MIT OR Apache-2.0 | RIPEMD-160 for the BIP-32 fingerprint (`HASH160`) |
| [chacha20poly1305](https://crates.io/crates/chacha20poly1305) | 0.10.1 | Apache-2.0 OR MIT | XChaCha20-Poly1305 sealing of the imported-seed root at rest |
| [p521](https://crates.io/crates/p521) | 0.13.3 | Apache-2.0 OR MIT | NIST P-521 secret-key construction for derived P-521 keys |
| [log](https://crates.io/crates/log) | 0.4 | MIT OR Apache-2.0 | Logging facade |

Dev-dependencies (host tests only, not shipped): [bip39](https://crates.io/crates/bip39) 2.2.2 (CC0-1.0) — an independent BIP-39 implementation used only as a cross-check in `tests/import.rs`; [ed25519-dalek](https://crates.io/crates/ed25519-dalek) 2.2.0 and [x25519-dalek](https://crates.io/crates/x25519-dalek) 2.0.1 (both BSD-3-Clause) — library-independence proof that the derived Ed25519/X25519 key material matches an implementation other than rpgp; [num-bigint](https://crates.io/crates/num-bigint) 0.4.6 (MIT OR Apache-2.0) — independent cross-check of the P-521 scalar reduction against a general-purpose bignum library.

## Vendored code

| Component | Origin | Role |
|---|---|---|
| `vendor/getrandom/` | KeyOS source (getrandom 0.2 fork) | Entropy override: hardware TRNG server on KeyOS builds, stock behavior on host |
| `vendor/security-api/` | KeyOS v1.2.1 source, adapted to SDK 0.4.0 conventions | `os/security` API client (`GetAppSeed`) |
| `pgp-core/src/import/bip39.rs` + `english.txt` | Canonical copy of `graffito/notes-core/src/bip39.rs` (same workspace, same author) | Plain BIP-39 mnemonic/wordlist handling for the imported-seed root; edited at the notes-core copy and re-copied, not forked |

## Foundation SDK / KeyOS platform

Provided by the installed Foundation SDK (path dependencies, not crates.io):

| Component | Role |
|---|---|
| `server` (KeyOS) | App runtime, KeyOS service messaging, filesystem API |
| `xous-api-log` | Log output to the KeyOS log server |
| `slint-keyos-platform` (+ `-build`) | [Slint](https://slint.dev) UI runtime, QR rendering, and build integration for KeyOS |
| `foundation-themes` | Design tokens and light/dark theming |

The Slint UI toolkit itself is licensed under GPL-3.0-only OR the Slint
Royalty-free / commercial licenses. **This app elects the GPL**, which is why
it is GPL-3.0-or-later. That is not a free choice: section 3 of the Slint
Royalty-free license excludes embedded systems, and a Passport Prime is one, so
on-device the GPL is the only option that costs nothing. KeyOS's own API crates
(`server`, `fs`, `crypto`, `security`, ...) are GPL-3.0-or-later as well. Taking
this app closed-source would require a paid Slint license *and* a resolution of
the KeyOS side.

## Artwork

| Asset | Origin | License |
|---|---|---|
| `ui/icons/*.svg` | Adapted from [Lucide](https://lucide.dev) | ISC |
| `resources/icon.svg`, `resources/icon-dark.svg` | Original ByteApps artwork | Same as the app |
