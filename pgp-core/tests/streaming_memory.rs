//! THE IMPORTANT TEST: proves `encrypt_stream`/`decrypt_stream` run in
//! constant memory, not just that they compile against streaming-shaped
//! signatures. A KeyOS process has ~59-60 MB of free heap (see the
//! workspace's "App memory limits" doc); the byte-oriented path this
//! streaming path replaces buffered a decrypted/encrypted file THREE times
//! over, which is exactly the shape of bug this test is built to catch.
//!
//! Its own `#[global_allocator]` tracks live and peak-live heap bytes
//! process-wide, so this file deliberately contains exactly ONE `#[test]` —
//! a second test running concurrently in the same process would corrupt the
//! peak measurement (the allocator can't tell which test an allocation
//! belongs to). Do not add more tests here; put them in another file.
//!
//! This is proven "real" (not silently green before and after — see the
//! workspace's `silent-green-test-hazards` lesson) by MUTATION: temporarily
//! reverting `encrypt_stream`/`decrypt_stream`'s bodies to buffer the whole
//! file (`read_to_end` + `MessageBuilder::from_bytes`/`Message::decrypt` +
//! `as_data_vec`/`to_vec`, matching the old `encrypt_bytes`/`decrypt_bytes`
//! implementation) while keeping the streaming signatures intact makes this
//! test FAIL with a multi-hundred-MB peak. See the PR/commit description
//! for the observed before/after numbers.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::RefCell;
use std::io::{Read, Write};
use std::rc::Rc;
use std::sync::atomic::{AtomicUsize, Ordering};

use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Tracking global allocator
// ---------------------------------------------------------------------------

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

struct TrackingAlloc;

unsafe impl GlobalAlloc for TrackingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            note_alloc(layout.size());
        }
        ptr
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc_zeroed(layout) };
        if !ptr.is_null() {
            note_alloc(layout.size());
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) };
        LIVE.fetch_sub(layout.size(), Ordering::SeqCst);
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let new_ptr = unsafe { System.realloc(ptr, layout, new_size) };
        if !new_ptr.is_null() {
            if new_size >= layout.size() {
                note_alloc(new_size - layout.size());
            } else {
                LIVE.fetch_sub(layout.size() - new_size, Ordering::SeqCst);
            }
        }
        new_ptr
    }
}

fn note_alloc(size: usize) {
    let live = LIVE.fetch_add(size, Ordering::SeqCst) + size;
    PEAK.fetch_max(live, Ordering::SeqCst);
}

fn current_live() -> usize {
    LIVE.load(Ordering::SeqCst)
}

fn current_peak() -> usize {
    PEAK.load(Ordering::SeqCst)
}

/// Collapse the peak back down to the current live-byte count, so growth
/// measured afterward reflects only what happens next.
fn reset_peak() {
    PEAK.store(current_live(), Ordering::SeqCst);
}

#[global_allocator]
static ALLOCATOR: TrackingAlloc = TrackingAlloc;

// ---------------------------------------------------------------------------
// Deterministic synthetic plaintext — generated on the fly, never buffered
// ---------------------------------------------------------------------------

const PLAINTEXT_LEN: u64 = 64 * 1024 * 1024; // 64 MiB
const SEED: u64 = 0x00C0_FFEE_1234_5678;
const MAX_PEAK_GROWTH: usize = 8 * 1024 * 1024; // 8 MiB budget

/// splitmix64 — deterministic, NOT cryptographic, just a reproducible
/// stream of bytes so the test needs no fixture on disk.
fn splitmix64_next(state: &mut u64) -> [u8; 8] {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^= z >> 31;
    z.to_le_bytes()
}

/// A `Read` that emits `len` bytes of the splitmix64 stream seeded from
/// `seed`, generating each chunk on demand. Never allocates more than the
/// caller's own read buffer — no internal `Vec`.
///
/// Carries any unread tail of the current 8-byte splitmix64 output across
/// `read()` calls (`chunk`/`chunk_pos`) rather than starting a fresh chunk
/// on every call. Without that, the emitted byte stream would depend on
/// exactly how the caller sizes its read buffers — e.g. two calls of 5 and
/// 3 bytes would drop 3 bytes a single 8-byte call would have kept — and
/// would silently diverge from `expected_hash_and_len`'s single continuous
/// pass over the same seed. (An earlier version of this test had exactly
/// that bug: it passed peak-heap but failed the hash comparison, because
/// the "expected" and "actual" sides of the comparison used the same
/// generator function but disagreed on where chunk boundaries fell.)
struct SyntheticReader {
    remaining: u64,
    state: u64,
    chunk: [u8; 8],
    chunk_pos: usize,
}

impl SyntheticReader {
    fn new(seed: u64, len: u64) -> Self {
        // chunk_pos == 8 means "no unread bytes left in `chunk`", forcing
        // the first read() to generate one before consuming anything.
        Self { remaining: len, state: seed, chunk: [0; 8], chunk_pos: 8 }
    }
}

impl Read for SyntheticReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.remaining == 0 {
            return Ok(0);
        }
        let want = (buf.len() as u64).min(self.remaining) as usize;
        let mut i = 0;
        while i < want {
            if self.chunk_pos == 8 {
                self.chunk = splitmix64_next(&mut self.state);
                self.chunk_pos = 0;
            }
            let avail = 8 - self.chunk_pos;
            let n = avail.min(want - i);
            buf[i..i + n].copy_from_slice(&self.chunk[self.chunk_pos..self.chunk_pos + n]);
            self.chunk_pos += n;
            i += n;
        }
        self.remaining -= want as u64;
        Ok(want)
    }
}

/// Recomputes the hash and length of the same splitmix64 stream
/// `SyntheticReader` produces, independently, so the "expected" side of the
/// final comparison never shares state with the reader that fed
/// `encrypt_stream` — an honest check that the bytes that came out the
/// other end of encrypt+decrypt are the bytes that went in.
fn expected_hash_and_len(seed: u64, len: u64) -> ([u8; 32], u64) {
    let mut hasher = Sha256::new();
    let mut state = seed;
    let mut remaining = len;
    while remaining > 0 {
        let chunk = splitmix64_next(&mut state);
        let n = remaining.min(8) as usize;
        hasher.update(&chunk[..n]);
        remaining -= n as u64;
    }
    (hasher.finalize().into(), len)
}

// ---------------------------------------------------------------------------
// A `Write` sink that discards bytes but hashes/counts them via shared
// state — so the hash/count survive even though `encrypt_stream`/
// `decrypt_stream` consume the sink by value and never hand it back.
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct HashState(Rc<RefCell<(Sha256, u64)>>);

impl HashState {
    fn new() -> Self {
        Self(Rc::new(RefCell::new((Sha256::new(), 0))))
    }

    fn finish(&self) -> ([u8; 32], u64) {
        let (hasher, count) = &*self.0.borrow();
        (hasher.clone().finalize().into(), *count)
    }
}

struct HashingWriter<W> {
    inner: W,
    state: HashState,
}

impl<W: Write> Write for HashingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.inner.write(buf)?;
        let mut s = self.state.0.borrow_mut();
        s.0.update(&buf[..n]);
        s.1 += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

// ---------------------------------------------------------------------------

#[test]
fn streaming_encrypt_decrypt_peak_heap_stays_bounded() {
    const PASS: &str = "streaming-mem-pass";

    // Key generation is NOT part of what this test measures — reset the
    // peak counter after it, per the brief, so RSA/EC scalar-mult scratch
    // and rpgp's own key-assembly allocations don't count against the
    // encrypt/decrypt budget.
    let key = pgp_core::generate_p521("Streaming Mem", "mem@example.com", Some(PASS)).unwrap();
    let pk = pgp_core::PgpKey::Secret(key.clone());

    let cipher_path = std::env::temp_dir()
        .join(format!("pgp-core-streaming-mem-{}.gpg", std::process::id()));
    let _ = std::fs::remove_file(&cipher_path); // stale file from a crashed prior run

    reset_peak();
    let baseline = current_live();

    // --- encrypt: synthetic on-the-fly generator -> tempfile (never a Vec) ---
    let cipher_state = HashState::new();
    {
        let src = SyntheticReader::new(SEED, PLAINTEXT_LEN);
        let dst = HashingWriter {
            inner: std::fs::File::create(&cipher_path).expect("create cipher tempfile"),
            state: cipher_state.clone(),
        };
        pgp_core::encrypt_stream(&pk, "big.bin", src, dst, None)
            .expect("encrypt_stream failed");
    }
    let (_cipher_hash, cipher_len) = cipher_state.finish();
    eprintln!("ciphertext: {cipher_len} bytes for {PLAINTEXT_LEN} bytes of plaintext");

    // --- decrypt: BufReader over that tempfile -> discarding hash sink ---
    // (never a Vec; the ciphertext is read back exactly as the device would
    // read a file, per the brief.)
    let plain_state = HashState::new();
    {
        let src = std::io::BufReader::new(
            std::fs::File::open(&cipher_path).expect("open cipher tempfile"),
        );
        let dst = HashingWriter { inner: std::io::sink(), state: plain_state.clone() };
        pgp_core::decrypt_stream(&key, PASS, src, dst, u64::MAX)
            .expect("decrypt_stream failed");
    }
    let (decrypted_hash, decrypted_len) = plain_state.finish();

    let _ = std::fs::remove_file(&cipher_path);

    let growth = current_peak().saturating_sub(baseline);
    eprintln!(
        "peak heap growth over encrypt+decrypt of {} MiB: {} bytes ({:.2} MiB)",
        PLAINTEXT_LEN / (1024 * 1024),
        growth,
        growth as f64 / (1024.0 * 1024.0)
    );
    assert!(
        growth < MAX_PEAK_GROWTH,
        "peak heap growth {growth} bytes exceeded the {MAX_PEAK_GROWTH}-byte (8 MiB) budget — \
         streaming is buffering the whole file somewhere"
    );

    let (expected_hash, expected_len) = expected_hash_and_len(SEED, PLAINTEXT_LEN);
    assert_eq!(decrypted_len, expected_len, "decrypted byte count does not match the input");
    assert_eq!(decrypted_hash, expected_hash, "decrypted content hash does not match the input");
}
