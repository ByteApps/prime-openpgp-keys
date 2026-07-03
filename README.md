# PGP Keychain — a Passport Prime app

An OpenPGP key manager for Foundation's **Passport Prime**, built as a Rust
binary with a **Slint** UI on **KeyOS** (Foundation's Rust microkernel on
Xous). Create, import, inspect, edit, and export OpenPGP keys, and **sign
arbitrary files** with them — including keys **derived deterministically
from the device's master seed**, so a seed phrase restore recovers your PGP
identity.

<p align="center">
  <img src="screenshots/keychain.png" alt="Keychain list" width="280">
  &nbsp;
  <img src="screenshots/key-detail.png" alt="Key detail" width="280">
  &nbsp;
  <img src="screenshots/derive-from-seed.png" alt="Derive from seed" width="280">
</p>

## Features

- **Create keys**: random RSA (2048/3072/4096), or **"From seed"** — an
  Ed25519 key (+ Cv25519 encryption subkey) derived from the wallet master
  seed via the KeyOS `GetAppSeed` service. The same account number always
  re-creates the same key and fingerprint, on this device or after a
  seed-phrase restore.
- **Import `.asc`** armored files (public or secret) from Internal, Airlock,
  or USB — any commonly supported algorithm parses: RSA, DSA/ElGamal,
  ECDSA/ECDH (NIST curves), Ed25519/Cv25519. Multi-key files work in both
  real-world shapes (one block with several keys, or concatenated blocks),
  and importing a public copy never downgrades a stored secret key.
- **Inspect**: fingerprint, key ID, algorithm and size/curve, creation and
  expiration dates, user IDs, subkeys with usage flags, secret-material
  status.
- **Edit** (secret keys): extend or clear the **expiration**, **add/remove
  user IDs**, and **change or remove the passphrase** — implemented as
  proper self-signature rebuilds that GnuPG verifies.
- **Sign files** (secret keys): pick any file on Internal, Airlock, or USB
  and write a detached binary OpenPGP signature next to it as `<file>.sig` —
  the same output as `gpg --detach-sign`, verifiable anywhere with
  `gpg --verify <file>.sig <file>`.
- **Sign over QR** (secret keys): scan arbitrary data with the device camera
  via the OS QR scanner — single QR codes or **multi-part animated UR**
  (BC-UR, reassembled by the OS) — then the armored detached signature is
  displayed as a QR code to scan back with your phone. A fully air-gapped
  sign loop: data in by camera, signature out by screen.
- **Encrypt / decrypt files**: encrypt any file on Internal/Airlock/USB to a
  key's encryption subkey, written next to it as `<file>.gpg` (binary
  AES-256, exactly what `gpg -e` produces and `gpg -d` reads). Encrypt works
  with any stored key — including public-only recipient keys — and an
  optional "Also sign" toggle embeds a signature (secret keys, `gpg -se`
  style). Decrypt (secret keys) accepts binary or armored input and restores
  the original filename by stripping `.gpg`/`.pgp`/`.asc`.
- **Export**: public-only or full secret key (behind a danger confirmation),
  to Internal or Airlock.
- Keys live as one armored file per key in `/pgp-keys` on Internal storage —
  on real hardware that volume is XTS-AES-256 encrypted with PIN-derived
  keys, and secret keys carry their own OpenPGP passphrase layer on top.

Everything runs offline — Prime has no network stack by design; there is no
keyserver access, and key material only moves through explicit file
import/export.

## Crypto stack

Pure-Rust [rpgp](https://github.com/rpgp/rpgp) (`pgp 0.20`, ≥ 0.19 for
CVE-2026-21895) with RustCrypto backends — no C dependencies. Entropy comes
from the platform: on hardware builds, a vendored KeyOS `getrandom` override
sources the os TRNG server; on the simulator (a host build) it's the OS
CSPRNG. Seed derivation is `HKDF-SHA256(HMAC-SHA256(app-id, master-seed),
account-index)` driving a ChaCha20 stream, with a fixed creation timestamp so
fingerprints reproduce exactly. All armor parsing is `catch_unwind`-guarded —
imported files are untrusted input.

## Build & run

Requires the `foundation` CLI (on `PATH` at `~/.foundation/sdk/bin`) and Nix.
In a non-login shell, source Nix first:

```bash
. '/nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh'
export PATH="$HOME/.foundation/sdk/bin:$PATH"
```

Then, from this directory (via the SDK's Nix dev shell):

```bash
nix develop ~/.foundation/sdk/current --command foundation sim     # hosted simulator
nix develop ~/.foundation/sdk/current --command foundation build   # compile + sign a hardware bundle
nix develop ~/.foundation/sdk/current --command cargo test -p pgp-core   # host test suite
```

> **Hardware sideload** (`foundation sideload`) is **not** possible on a retail
> Prime — it needs dev firmware from Foundation. The simulator is the
> verification target. See `NOTES.md`.

## Testing

All OpenPGP logic lives in the UI-free **`pgp-core/`** subcrate so it can be
tested on the host: 37 tests covering per-algorithm parsing against
gpg-generated fixtures, generation round-trips, every edit operation,
detached-signing round-trips (binary and armored, with tamper rejection)
across RSA, Ed25519, and NIST P-256, encrypt/decrypt round-trips (including
public-key-encrypt → secret-decrypt and sign-then-encrypt), seed derivation
determinism (uid/passphrase independence, index separation), and **GnuPG
interop** — the suite shells out to a real `gpg` in a throwaway `GNUPGHOME`
to prove our exports import, our edited keys verify, our rotated passphrases
unlock signing, our detached signatures come back `GOODSIG` from
`gpg --verify`, gpg decrypts our `.gpg` files (and we decrypt gpg's, binary
and armored), and our sign-then-encrypt output shows `GOODSIG` under
`gpg -d` (all skipped cleanly when gpg is absent). A workspace-level
simulator UI test (`../ui-automation/tests/pgp-keychain.sh`, 18 steps) drives
every flow through real taps and the on-screen keyboard, including signing a
file, an encrypt → decrypt round-trip, opening/cancelling the QR scanner (the
hosted sim streams the real Mac webcam), and derive → delete → re-derive
reproducing the same fingerprint.

## Permissions

Declared in `app-config.toml` → `[permissions]`:
`template = ["gui-app", "fs-generic", "fs-access"]` (UI + read/write
filesystem across `User`/`Airlock`/`USB`) plus `"os/security" =
["GetAppSeed"]` for seed derivation. Enforced at compile time (undeclared
calls fail to build) and by the KeyOS kernel at runtime.

## Project layout

- `pgp-core/` — UI-free OpenPGP library (parse/generate/derive/edit/export)
  with the test suite and gpg-generated fixtures.
- `src/main.rs` — app logic: screens, `/pgp-keys` persistence, callbacks.
- `ui/app.slint`, `ui/callbacks.slint` — the UI and the Slint↔Rust bridge.
- `vendor/getrandom/` — KeyOS's getrandom override (TRNG on hardware).
- `vendor/security-api/` — KeyOS `os/security` API crate (GetAppSeed),
  adapted to the installed SDK's server conventions.
- `app-config.toml` / `permission_templates.toml` — hand-edited config
  (`manifest.toml` is generated; don't hand-edit).

See **`CLAUDE.md`** for architecture detail and **`NOTES.md`** for build
verification logs and the non-obvious gotchas (rpgp armor splitting,
gpg-agent caching in tests, the getrandom patch mechanics, SDK version
adaptation of the security API).

## Notes

Scaffolded from `foundation new prime-pgp-keychain --template default-app`,
then customized. Normally checked out as a git submodule of a `prime/`
workspace (alongside a local KeyOS docs knowledge base); it also builds
standalone. Verified: signed hardware build (10.9 MB), full simulator UI test
run, and gpg cross-validation — see `NOTES.md`.
