# <img src="resources/icon.svg" alt="" width="42" align="top" /> PGP Keychain

**Security · OpenPGP** — a complete OpenPGP key manager that lives where your keys belong: on secure hardware, offline.

PGP Keychain turns your Passport Prime into a personal certificate authority. Create keys, import the ones you already have, sign and encrypt files, and answer signing requests over nothing but QR codes — all on a device with no network stack and storage encrypted by your PIN. Best of all: keys can be **derived from your device's master seed**, so restoring your seed phrase restores your PGP identity too.

<p align="center">
  <img src="screenshots/keychain.png" alt="Keychain list" width="280">
  &nbsp;
  <img src="screenshots/key-detail.png" alt="Key detail" width="280">
  &nbsp;
  <img src="screenshots/derive-from-seed.png" alt="Derive from seed" width="280">
</p>

## Features

- **Create keys** — random RSA (2048/3072/4096), or **"From seed"**: an Ed25519 key (with encryption subkey) derived from your wallet master seed. The same account number always re-creates the same key and fingerprint — on this device, or on a new one after a seed-phrase restore.
- **Import anything standard** — armored `.asc` files (public or secret) from Internal, Airlock, or USB. RSA, DSA/ElGamal, ECDSA/ECDH, Ed25519 all parse, multi-key files work, and importing a public copy never downgrades a stored secret key.
- **Inspect and edit** — fingerprints, subkeys, user IDs, expiration at a glance; extend or clear expiration, add/remove user IDs, change or remove the passphrase — all as proper self-signature rebuilds that GnuPG verifies.
- **Sign files** — pick any file on the device and get a detached `.sig` next to it, identical to `gpg --detach-sign` output and verifiable anywhere.
- **Sign over QR** — a fully air-gapped signing loop: scan data with the device camera (single QR or animated multi-part UR), approve, and the signature comes back as a QR on the screen. Data in by camera, signature out by display — no cable, ever.
- **Encrypt & decrypt files** — output is exactly what `gpg -e` produces and `gpg -d` reads, with an optional embedded signature. Encrypt to any stored key, including public-only recipient keys.
- **Export safely** — public-only by default; full secret export sits behind a danger confirmation.
- **GnuPG-interoperable by proof** — the test suite round-trips keys, signatures, and encrypted files through a real `gpg` to hold the compatibility line.

Keys live as armored files on Internal storage — on hardware, a volume encrypted with PIN-derived keys — and secret keys keep their own OpenPGP passphrase layer on top. There is no keyserver access and no background sync: key material only moves when you explicitly import or export it.

## Get it running

With the Foundation SDK installed, build and launch in the simulator with:

```bash
foundation sim
```

## Learn more

- [THIRD-PARTY.md](THIRD-PARTY.md) — libraries this app is built on

## Support

If this app is useful to you, a small bitcoin donation is always appreciated — entirely optional.

<div align="center">

<img src="donate-qr.png" alt="Donate bitcoin" width="200">

**`bc1qkmg7qek6vuuw6hqp9sm06krzcr7pwd5jhcr43f`**

</div>

Donations help cover development costs and keep more open-source bitcoin tools coming. No VC funding, no ads, no tracking.

## License & disclaimer

Licensed under the GNU General Public License v3.0 or later — see [COPYING](COPYING). Sections 15–17 of that license disclaim all warranty and limit liability; the notes below restate that in plain language.

The **`pgp-core/`** library inside this repository carries its own, more permissive terms: **MIT OR Apache-2.0**, see [`pgp-core/LICENSE-MIT`](pgp-core/LICENSE-MIT) and [`pgp-core/LICENSE-APACHE`](pgp-core/LICENSE-APACHE). It holds the OpenPGP key operations, and the split is deliberate — other projects, including non-GPL peers of this app, are meant to build on that crate. The GPL above covers the application around it.

This is experimental software and it has **not been independently audited**.
It is provided **"as is", without warranty of any kind**, express or implied,
including but not limited to the warranties of merchantability, fitness for a
particular purpose, and non-infringement.

**Use it at your own risk.** To the maximum extent permitted by law, in no
event shall the authors, copyright holders, or contributors be liable for any
claim, damages, or other liability — including, without limitation,
**loss of keys, loss of encrypted data, or any other loss of data** — whether in an action of contract, tort, or
otherwise, arising from, out of, or in connection with this software or its
use.

Nothing in this project is financial, investment, legal, or tax advice. You
are solely responsible for verifying addresses, amounts, fees, and backups
before moving funds, and for complying with the laws of your jurisdiction.
Test on test networks, or with amounts you can afford to lose, first.

If a private key is lost, or its passphrase forgotten, **data encrypted to it is unrecoverable** — there is no reset or recovery service. Verify key fingerprints out-of-band before trusting an imported key or encrypting to it.
