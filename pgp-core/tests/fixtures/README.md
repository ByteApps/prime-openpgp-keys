# Test fixtures

Generated with GnuPG 2.2.41 (MacGPG2) in a throwaway `GNUPGHOME`. Every
secret key is protected with the passphrase `fixture-pass`. `Expire-Date: 0`
(never expires) everywhere.

| fixture | batch parameters |
| --- | --- |
| `rsa2048-*` | `Key-Type: RSA`, `Key-Length: 2048`, `Subkey-Type: RSA`, `Subkey-Length: 2048` |
| `rsa4096-*` | `Key-Type: RSA`, `Key-Length: 4096`, `Subkey-Type: RSA`, `Subkey-Length: 4096` |
| `dsa-elgamal-*` | `Key-Type: DSA`, `Key-Length: 2048`, `Subkey-Type: ELG-E`, `Subkey-Length: 2048` |
| `ed25519-cv25519-*` | `Key-Type: EDDSA`, `Key-Curve: ed25519`, `Subkey-Type: ECDH`, `Subkey-Curve: cv25519` |
| `nistp256-*` | `Key-Type: ECDSA`, `Key-Curve: nistp256`, `Subkey-Type: ECDH`, `Subkey-Curve: nistp256` |
| `nistp521-*` | `Key-Type: ECDSA`, `Key-Curve: nistp521`, `Subkey-Type: ECDH`, `Subkey-Curve: nistp521` (added 2026-08-19, same GnuPG 2.2.41, for the P-521 generation tier) |

Each key was generated via `gpg --batch --pinentry-mode loopback --gen-key`
with `Name-Real: Fixture <name>`, `Name-Email: <name>@example.com`, then
exported with `gpg --armor --export <fpr>` (public) and
`gpg --pinentry-mode loopback --passphrase fixture-pass --armor
--export-secret-keys <fpr>` (secret).

Special files:

- `expected_fprs.txt` — `name=FINGERPRINT` per fixture, captured from
  `gpg --list-keys --with-colons` at generation time; tests assert against it.
- `gpg-list-keys-colons.txt` — full colon-format listing at generation time,
  for reference.
- `two-keys-concatenated.asc` — `cat rsa2048-public.asc
  ed25519-cv25519-public.asc` (two armor blocks in one file).
- `two-keys-single-block.asc` — `gpg --armor --export <rsa2048>
  <ed25519-cv25519>` (one armor block holding two keys).
- `garbage.asc` — not PGP data at all.
- `truncated.asc` — first 400 bytes of `rsa2048-public.asc`.
