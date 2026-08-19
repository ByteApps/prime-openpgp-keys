# Third-party libraries

Direct dependencies of this app and its `pgp-core` library. The complete transitive list (with exact versions) is pinned in [`Cargo.lock`](Cargo.lock).

## Rust crates

| Library | Version | License | Used for |
|---|---|---|---|
| [pgp](https://github.com/rpgp/rpgp) (rpgp) | 0.20.0 (pinned) | MIT OR Apache-2.0 | Pure-Rust OpenPGP: parsing, key generation, signing, encryption |
| [rsa](https://crates.io/crates/rsa) | 0.9 | MIT OR Apache-2.0 | RSA key introspection (modulus sizes; same copy rpgp uses) |
| [hkdf](https://crates.io/crates/hkdf) | 0.12 | MIT OR Apache-2.0 | Seed-derived keys: HKDF-SHA256 expansion of the device app-seed |
| [sha2](https://crates.io/crates/sha2) | 0.10 | MIT OR Apache-2.0 | SHA-256 for derivation |
| [rand](https://crates.io/crates/rand) | 0.8 | MIT OR Apache-2.0 | RNG plumbing for key generation |
| [rand_chacha](https://crates.io/crates/rand_chacha) | 0.3 | MIT OR Apache-2.0 | Deterministic ChaCha20 stream for seed-derived keys |
| [log](https://crates.io/crates/log) | 0.4 | MIT OR Apache-2.0 | Logging facade |

## Vendored code

| Component | Origin | Role |
|---|---|---|
| `vendor/getrandom/` | KeyOS source (getrandom 0.2 fork) | Entropy override: hardware TRNG server on KeyOS builds, stock behavior on host |
| `vendor/security-api/` | KeyOS v1.2.1 source, adapted to SDK 0.4.0 conventions | `os/security` API client (`GetAppSeed`) |

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
