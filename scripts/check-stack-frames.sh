#!/usr/bin/env bash
# Worst-case stack depth per pgp-core operation, measured on the ARM binary.
#
# WHY THIS EXISTS
# ---------------
# KeyOS gives a process a 256 KB stack (keyos::STACK_PAGE_COUNT = 64 x 4 KB,
# growing down from USER_STACK_BOTTOM = 0x6ff0_0000). rustc gives the derived
# `Clone` impls of rpgp's PQC-laden enums ENORMOUS frames -- 177 KB for
# `SignedSecretKey::clone`, 145 KB for `PublicParams::clone` -- because each
# match arm gets its own stack slot for every `draft-pqc` variant. `size_of`
# tells you nothing: `PublicParams` is 304 bytes.
#
# On 2026-08-20 that shipped as a device crash: creating a seed-derived
# Ed25519 key with a 2-year expiry died with
#   Invalid memory access (L2): PID 42 attempted to write address 0x6feaf648
#   (0x109b8 bytes below stack) (DFSR 0x00000877)
# 0x109b8 = 68,024 = exactly how far `set_expiration` -> SignedSecretKey::clone
# (177 KB) -> PublicParams::clone (145 KB) = 322 KB overran the 256 KB stack.
#
# THE SIMULATOR CANNOT CATCH THIS. A macOS thread has an 8 MB stack, so every
# one of these paths passes in the sim and in `cargo test`. This script is the
# only check that fails.
#
# Usage:  scripts/check-stack-frames.sh [path/to/elf]
# Run it inside the SDK Nix shell (needs arm-none-eabi-objdump):
#   nix develop ~/.foundation/sdk/current --command scripts/check-stack-frames.sh
set -euo pipefail

ELF="${1:-target/armv7a-unknown-xous-elf/release/prime-openpgp-keys}"
BUDGET="${STACK_BUDGET:-262144}"   # KeyOS user stack, bytes

[ -f "$ELF" ] || { echo "no ELF at $ELF -- run 'foundation build --release' first" >&2; exit 2; }
command -v arm-none-eabi-objdump >/dev/null || {
  echo "arm-none-eabi-objdump not found -- run inside the SDK Nix shell" >&2; exit 2; }

DIS="$(mktemp -t stackframes.XXXXXX)"
trap 'rm -f "$DIS"' EXIT
arm-none-eabi-objdump -d --demangle "$ELF" > "$DIS"

ELF="$ELF" DIS="$DIS" BUDGET="$BUDGET" python3 - <<'PY'
import os, re, sys
sys.setrecursionlimit(200000)
BUDGET = int(os.environ["BUDGET"])

fn_re   = re.compile(r'^[0-9a-f]{8} <(.+)>:$')
sub_re  = re.compile(r'\bsub(?:\.w|s)?\s+sp,\s*sp,\s*#(\d+)')
# NOTE: objdump prints trait-impl targets as <<T as Trait>::method> -- the name
# itself contains '>', so this MUST be greedy to end-of-line. A [^>]+ capture
# silently truncates every trait method and makes the whole graph look empty.
bl_re   = re.compile(r'\bbl(?:x)?(?:\.w)?\s+[0-9a-f]+\s+<(.+)>\s*$')

# Algorithms the app can neither create nor hold: nothing in the UI generates
# them and RFC 9980 puts them on v6 keys only, while this app is v4-only.
# Their arms carry 350 KB frames that would swamp every measurement.
PRUNE = ('ml_dsa','MlDsa','slh_dsa','SlhDsa','ml_kem1024','MlKem1024',
         'x448','X448','Ed448','ed448')

frames, edges, cur = {}, {}, None
for line in open(os.environ["DIS"], errors='ignore'):
    line = line.rstrip()
    m = fn_re.match(line)
    if m:
        cur = m.group(1); frames.setdefault(cur, 0); edges.setdefault(cur, set()); continue
    if not cur:
        continue
    s = sub_re.search(line)
    if s:
        frames[cur] = max(frames[cur], int(s.group(1)))
    b = bl_re.search(line)
    if b and not any(x in b.group(1) for x in PRUNE):
        edges[cur].add(b.group(1))

memo, onstack = {}, set()
def depth(f):
    if f in memo: return memo[f]
    if f in onstack: return (0, [])          # recursion: cut the cycle
    onstack.add(f)
    best = (0, [])
    for c in edges.get(f, ()):
        d, path = depth(c)
        if d > best[0]: best = (d, path)
    onstack.discard(f)
    memo[f] = (frames.get(f, 0) + 8 + best[0], [f] + best[1])   # +8 = saved regs
    return memo[f]

ops = sorted(k for k in frames if k.startswith('pgp_core::') and '::{' not in k)
if not ops:
    print("no pgp_core symbols found -- is this the right ELF?", file=sys.stderr); raise SystemExit(2)

rows = sorted(((depth(o)[0], o) for o in ops), reverse=True)
over = [(d, o) for d, o in rows if d > BUDGET]

print(f"KeyOS stack budget: {BUDGET:,} bytes   ELF: {os.environ['ELF']}")
print(f"{'worst-case':>12}  {'headroom':>10}  operation")
for d, o in rows[:15]:
    print(f"{d:>12,}  {BUDGET-d:>10,}  {o.replace('pgp_core::','')}")

if over:
    print(f"\nFAIL: {len(over)} operation(s) exceed the {BUDGET:,}-byte KeyOS stack.\n")
    for d, o in over:
        print(f"  {o} needs {d:,} bytes ({d-BUDGET:,} over):")
        acc = 0
        for fn in depth(o)[1][:10]:
            acc += frames.get(fn, 0) + 8
            print(f"      {frames.get(fn,0):>8}  (cum {acc:>8})  {fn[:88]}")
    print("\nUsually this is a key type being CLONED. Editing operations must take")
    print("`key: SignedSecretKey` BY VALUE -- see the pgp_core module docs.")
    raise SystemExit(1)

print(f"\nOK: all {len(rows)} pgp-core operations fit (tightest: {rows[0][1].replace('pgp_core::','')}, "
      f"{BUDGET-rows[0][0]:,} bytes to spare).")
PY
