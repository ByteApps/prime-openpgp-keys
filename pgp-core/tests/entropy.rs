//! Entropy battery over the two real RNG sources the keygen path uses.
//!
//! Prompted by a 2026 public disclosure of an RNG failure in a
//! shipped hardware wallet's firmware: a hardware wallet
//! shipped key generation that silently used a deterministic PRNG (bug
//! #1), and a reseed where only 4 of 32 bytes reached the generator,
//! capping it at 2^32 states (bug #2).
//!
//! `generate_rsa` calls `params.generate(thread_rng())` — `rand 0.8`'s
//! `thread_rng()`, itself seeded through `rand_core 0.6` ->
//! `getrandom 0.2`, which on device is redirected by
//! `[patch.crates-io]` to `vendor/getrandom` (the KeyOS TRNG backend).
//! So there are two things worth exercising directly:
//!
//!   1. `getrandom::getrandom` — the OS/TRNG entry point itself.
//!   2. `rand::thread_rng()` — what rpgp's `generate()` actually consumes.
//!
//! The battery (`common/entropy_battery.rs`) is canonical and shared
//! byte-identical across four repos — see its own doc comment for what
//! it can and cannot prove. In particular it CANNOT catch the disclosed firmware bug
//! #1 (a fixed-seed CSPRNG is statistically perfect); that is
//! `tests/rng_backend.rs`'s job.

#[path = "common/entropy_battery.rs"]
mod battery;

use battery::controls;

// ---------------------------------------------------------------------
// The two real sources
// ---------------------------------------------------------------------

fn from_getrandom(out: &mut [u8]) {
    getrandom::getrandom(out).expect("getrandom::getrandom failed");
}

fn from_getrandom32(out: &mut [u8; 32]) {
    from_getrandom(&mut out[..]);
}

fn from_thread_rng(out: &mut [u8]) {
    use rand::RngCore;
    rand::thread_rng().fill_bytes(out);
}

fn from_thread_rng32(out: &mut [u8; 32]) {
    from_thread_rng(&mut out[..]);
}

// ---------------------------------------------------------------------
// Positive: getrandom::getrandom (the OS/TRNG entry point)
// ---------------------------------------------------------------------

#[test]
fn getrandom_passes_battery() {
    let r = battery::battery_from(32, from_getrandom);
    println!("{}", r.summary());
    r.assert_ok("getrandom::getrandom");
}

#[test]
fn getrandom_draw_sanity() {
    battery::draw_sanity(10_000, from_getrandom32).assert_ok("getrandom::getrandom draws");
}

#[test]
fn getrandom_collision_free() {
    let t = std::time::Instant::now();
    let r = battery::collision_freedom(from_getrandom32);
    println!("collision test took {:?}\n{}", t.elapsed(), r.summary());
    r.assert_ok("getrandom::getrandom collisions");
}

// ---------------------------------------------------------------------
// Positive: rand::thread_rng() (what rpgp's generate() consumes)
// ---------------------------------------------------------------------

#[test]
fn thread_rng_passes_battery() {
    let r = battery::battery_from(32, from_thread_rng);
    println!("{}", r.summary());
    r.assert_ok("rand::thread_rng()");
}

#[test]
fn thread_rng_draw_sanity() {
    battery::draw_sanity(10_000, from_thread_rng32).assert_ok("rand::thread_rng() draws");
}

#[test]
fn thread_rng_collision_free() {
    let t = std::time::Instant::now();
    let r = battery::collision_freedom(from_thread_rng32);
    println!("collision test took {:?}\n{}", t.elapsed(), r.summary());
    r.assert_ok("rand::thread_rng() collisions");
}

// ---------------------------------------------------------------------
// Negative controls — prove the battery discriminates. Ported from the
// validated reference harness; ONE base real source (getrandom) feeds
// the controls that need one, since the controls exercise the battery's
// power, not the specific real source wrapped by it.
// ---------------------------------------------------------------------

fn assert_fails(r: &battery::Report, expect: &[&str], what: &str) {
    assert!(!r.passed(), "{what} MUST fail the battery but passed:\n{}", r.summary());
    let failed = r.failed_names();
    for e in expect {
        assert!(
            failed.contains(e),
            "{what} should have tripped `{e}`; tripped {failed:?}\n{}",
            r.summary()
        );
    }
    println!("{what} correctly failed: {failed:?}");
}

#[test]
fn control_zeros_fails() {
    let r = battery::battery_from(32, controls::zeros);
    assert_fails(&r, &["not_degenerate", "monobit", "longest_run", "shannon_entropy"], "all-zero source");
}

#[test]
fn control_counter_fails() {
    let mut c = controls::Counter::default();
    let r = battery::battery_from(8, |o| c.fill(o));
    assert_fails(&r, &["byte_chi_square"], "counter source");
}

#[test]
fn control_truncated_fails() {
    // disclosure bug 2: 4 of every 32 bytes actually filled.
    let mut t = controls::Truncated { inner: from_getrandom, kept: 4 };
    let r = battery::battery_from(32, |o| t.fill(o));
    assert_fails(&r, &["monobit", "shannon_entropy"], "4-of-32-bytes source");
}

#[test]
fn control_stuck_bit_fails() {
    let mut s = controls::StuckBit(from_getrandom);
    let r = battery::battery_from(32, |o| s.fill(o));
    assert_fails(&r, &["bit_position_bias"], "stuck-low-bit source");
}

#[test]
fn control_biased_fails() {
    let mut s = controls::Biased(from_getrandom);
    let r = battery::battery_from(32, |o| s.fill(o));
    assert_fails(&r, &["monobit", "bit_position_bias"], "7-bit masked source");
}

#[test]
fn control_repeating_page_fails() {
    let mut s = controls::RepeatingPage::new(from_getrandom, 4096);
    let r = battery::battery_from(32, |o| s.fill(o));
    assert_fails(&r, &["repeated_blocks"], "never-refilled page");
}

#[test]
fn control_reseed32_caught_only_by_collisions() {
    // A perfect CSPRNG with a 32-bit state: passes the distribution
    // battery, caught by the birthday test. This is the whole reason
    // collision_freedom exists.
    let mut s = controls::Reseed32::new(1);
    let dist = battery::battery_from(32, |o| s.fill(o));
    println!("reseed32 distribution report:\n{}", dist.summary());

    let mut s2 = controls::Reseed32::new(7);
    let t = std::time::Instant::now();
    let coll = battery::collision_freedom(|o| s2.draw32(o));
    println!("reseed32 collision test took {:?}\n{}", t.elapsed(), coll.summary());
    assert!(!coll.passed(), "32-bit-state generator MUST collide within {} draws", battery::COLLISION_DRAWS);
}

#[test]
fn control_fixed_seed_passes_and_that_is_the_point() {
    // disclosure bug 1: statistically perfect, undetectable here. The
    // detectors are the backend/graph contract tests (rng_backend.rs)
    // and cross-boot independence on hardware.
    let mut s = controls::FixedSeed::new(0x42);
    let r = battery::battery_from(32, |o| s.fill(o));
    assert!(
        r.passed(),
        "a fixed-seed CSPRNG is expected to PASS the statistics; if it now \
         fails, the battery changed meaning:\n{}",
        r.summary()
    );
    let mut a = controls::FixedSeed::new(0x42);
    let mut b = controls::FixedSeed::new(0x42);
    let (mut x, mut y) = ([0u8; 32], [0u8; 32]);
    a.fill(&mut x);
    b.fill(&mut y);
    assert_eq!(x, y, "two instances of a fixed-seed PRNG must agree — that IS the bug shape");
}

// ---------------------------------------------------------------------
// The deterministic seed-derived path (`derive_ed25519`) is SUPPOSED to
// be deterministic — it is not a finding. What matters is that its
// determinism is intentional and scoped: same seed -> same key,
// different seeds -> different keys, and `generate_rsa` (the random
// path) never touches it.
// ---------------------------------------------------------------------

fn fingerprint_of(seed: &[u8; 32], index: u32) -> String {
    let key = pgp_core::derive_ed25519(seed, index, "Test User", "test@example.com", None)
        .expect("derive_ed25519 failed");
    let info = pgp_core::key_info(&pgp_core::PgpKey::Secret(key));
    info.fingerprint
}

#[test]
fn derive_ed25519_same_seed_same_index_is_byte_identical() {
    let seed = [0x11u8; 32];
    let a = fingerprint_of(&seed, 0);
    let b = fingerprint_of(&seed, 0);
    assert_eq!(a, b, "same app_seed + same index must reproduce the same key — that is the whole point of seed-derived recovery");
}

#[test]
fn derive_ed25519_different_index_gives_different_key() {
    let seed = [0x11u8; 32];
    let a = fingerprint_of(&seed, 0);
    let b = fingerprint_of(&seed, 1);
    assert_ne!(a, b, "different index must diverge (HKDF info string is domain-separated by index)");
}

#[test]
fn derive_ed25519_different_seed_gives_different_key() {
    let a = fingerprint_of(&[0x11u8; 32], 0);
    let b = fingerprint_of(&[0x22u8; 32], 0);
    assert_ne!(a, b, "different app_seed must diverge");
}

/// Slice the source between one `pub fn NAME(` and the next top-level
/// `pub fn `, so the structural checks below look only at the function
/// body they name — not incidentally match text elsewhere in the file.
fn fn_source(name: &str) -> String {
    let src = include_str!("../src/lib.rs");
    let marker = format!("pub fn {name}(");
    let start = src.find(&marker).unwrap_or_else(|| panic!("`{marker}` not found in src/lib.rs"));
    let rest = &src[start..];
    let end = rest[marker.len()..]
        .find("\npub fn ")
        .map(|p| p + marker.len())
        .unwrap_or(rest.len());
    rest[..end].to_string()
}

#[test]
fn generate_rsa_never_uses_the_deterministic_stream() {
    let body = fn_source("generate_rsa");
    assert!(
        body.contains("thread_rng"),
        "generate_rsa no longer uses thread_rng() — random keygen must use the system RNG"
    );
    assert!(
        !body.contains("ChaCha20Rng") && !body.contains("from_seed"),
        "generate_rsa (the RANDOM keygen path) must never be reachable through the \
         deterministic seed-derived stream — a caller expecting fresh entropy would \
         silently get a reproducible key:\n{body}"
    );
}

#[test]
fn derive_ed25519_is_the_only_deterministic_path() {
    let body = fn_source("derive_ed25519");
    assert!(
        body.contains("ChaCha20Rng::from_seed"),
        "derive_ed25519 no longer derives its stream via ChaCha20Rng::from_seed — \
         either the intentional deterministic scheme changed (update this pin \
         deliberately) or it regressed:\n{body}"
    );
}

/// The recovery contract, pinned to a literal. `derive_ed25519`'s output
/// commits to the HKDF salt/info strings and to `DERIVED_KEY_CREATED_AT`
/// (a fingerprint covers the key's creation time), so any drift in those
/// silently strands every key a user derived before the change — their
/// seed would no longer reproduce the identity they published.
///
/// The sibling determinism tests above compare two runs of the SAME
/// build and cannot see that; only a literal captured from a known-good
/// build can. Preferences, user IDs and passphrases live in signature
/// packets rather than the public key packet, so changing them must NOT
/// move this value.
#[test]
fn derive_ed25519_fingerprint_is_pinned() {
    assert_eq!(
        fingerprint_of(&[0x11u8; 32], 0),
        "9D53AA0177D528C7B52545083FE08F54CA0D6AF1",
        "seed-derived identity changed — see the comment above before touching the expected value"
    );
}
