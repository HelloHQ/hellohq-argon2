//! Argon2id (RFC 9106, version 0x13) over a small, explicit C ABI.
//!
//! A thin, embeddable wrapper around RustCrypto's [`argon2`] 0.6.0 with lane
//! parallelism. It exposes exactly what HelloHQ's password derivations need
//! (Argon2id, no secret, no associated data) and nothing else:
//!
//! | C function | What it does |
//! |---|---|
//! | [`hqargon2_abi_version`] | ABI version; the Dart loader refuses one it does not know |
//! | [`hqargon2_backend_id`] | NUL-terminated id, e.g. `hellohq-argon2 0.1.0 (argon2 0.6.0 parallel)` |
//! | [`hqargon2id_derive`] | Argon2id v0x13 of a password and salt into a caller-owned buffer |
//!
//! Design rules, all enforced by tests:
//!
//! * every buffer has an explicit length; the cost (memory, passes, lanes) is
//!   an argument, never a constant here: the caller owns the policy;
//! * on **any** error or panic the output buffer is zeroed;
//! * no panic crosses the FFI boundary (`catch_unwind` → error code);
//! * the block matrix (64 MiB at HelloHQ's production cost) is an anonymous
//!   memory mapping owned by this crate, **wiped and unmapped before the call
//!   returns**, so its pages go back to the OS at once. argon2's own
//!   `hash_password_into` frees its matrix without wiping it, and through
//!   malloc, whose large-allocation cache kept the pages resident;
//! * nothing allocated here outlives a call, so there is no `free` function.
//!
//! **Threads.** The lanes of each slice run on rayon's process-wide pool (one
//! thread per logical CPU, started on first use). The calling thread blocks
//! until the key is derived and does not compute lanes itself. Concurrent
//! calls share the one pool; there is no timeout anywhere.
//!
//! [`argon2`]: https://crates.io/crates/argon2

use std::os::raw::c_char;
use std::panic::{catch_unwind, AssertUnwindSafe};

use argon2::{Algorithm, Argon2, Block, Params, Version};
use zeroize::Zeroize;

/// ABI version of the C interface. Bumped on any incompatible change; the Dart
/// loader refuses a library whose value it does not know.
pub const ABI_VERSION: u32 = 1;

/// NUL-terminated backend identity, checked by the app's loader.
static BACKEND_ID: &[u8] = concat!(
    "hellohq-argon2 ",
    env!("CARGO_PKG_VERSION"),
    " (argon2 0.6.0 parallel)\0"
)
.as_bytes();

/// Error codes returned by the C ABI. `0` is success.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// A required pointer was null.
    NullPointer = -1,
    /// A cost parameter is outside RFC 9106's limits: memory below 8 KiB per
    /// lane, zero passes, or lanes outside 1..=2^24-1.
    BadParams = -2,
    /// The salt is shorter than 8 bytes, or the output is outside 4..=2^32-1
    /// bytes.
    BadLength = -3,
    /// The block matrix could not be mapped (or its size overflows).
    OutOfMemory = -4,
    /// An internal panic was caught at the FFI boundary.
    InternalPanic = -5,
}

impl From<argon2::Error> for Error {
    fn from(e: argon2::Error) -> Self {
        use argon2::Error as E;
        match e {
            E::OutOfMemory => Error::OutOfMemory,
            E::MemoryTooLittle
            | E::MemoryTooMuch
            | E::TimeTooSmall
            | E::ThreadsTooFew
            | E::ThreadsTooMany
            | E::AlgorithmInvalid
            | E::VersionInvalid => Error::BadParams,
            _ => Error::BadLength,
        }
    }
}

/// The Argon2 block matrix in an anonymous private mapping: zero-filled by the
/// kernel (an all-zero [`Block`] is valid), page-aligned (a block needs 64),
/// wiped and unmapped on drop.
struct BlockMatrix {
    map: memmap2::MmapMut,
    blocks: usize,
}

impl BlockMatrix {
    fn new(blocks: usize) -> Result<Self, Error> {
        let bytes = blocks
            .checked_mul(core::mem::size_of::<Block>())
            .ok_or(Error::OutOfMemory)?;
        if bytes == 0 {
            return Err(Error::BadParams);
        }
        let map = memmap2::MmapOptions::new()
            .len(bytes)
            .map_anon()
            .map_err(|_| Error::OutOfMemory)?;
        Ok(Self { map, blocks })
    }

    fn as_blocks(&mut self) -> &mut [Block] {
        debug_assert_eq!(
            self.map.as_ptr() as usize % core::mem::align_of::<Block>(),
            0
        );
        // SAFETY: the mapping is exactly `blocks` blocks long, page-aligned
        // (>= Block's 64-byte alignment), zero-filled (a valid Block), and
        // exclusively borrowed through `&mut self`.
        unsafe {
            core::slice::from_raw_parts_mut(self.map.as_mut_ptr().cast::<Block>(), self.blocks)
        }
    }
}

impl Drop for BlockMatrix {
    fn drop(&mut self) {
        // Wipe before the pages are returned; `map` is unmapped right after.
        self.map.zeroize();
    }
}

/// Argon2id v0x13 (no secret, no associated data) of `pwd` and `salt` into
/// `out`, whose length is the tag length.
///
/// On error `out` is left untouched here; the C entry point zeroes it.
pub fn derive(
    pwd: &[u8],
    salt: &[u8],
    m_cost_kib: u32,
    t_cost: u32,
    p_cost: u32,
    out: &mut [u8],
) -> Result<(), Error> {
    if out.len() < Params::MIN_OUTPUT_LEN || out.len() > Params::MAX_OUTPUT_LEN {
        return Err(Error::BadLength);
    }
    if salt.len() < argon2::MIN_SALT_LEN {
        return Err(Error::BadLength);
    }
    let params = Params::new(m_cost_kib, t_cost, p_cost, Some(out.len()))?;
    let mut matrix = BlockMatrix::new(params.block_count())?;
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params).hash_password_into_with_memory(
        pwd,
        salt,
        out,
        matrix.as_blocks(),
    )?;
    Ok(())
    // `matrix` is wiped and unmapped here, on success and on error alike.
}

/// ABI version this library speaks.
#[no_mangle]
pub extern "C" fn hqargon2_abi_version() -> u32 {
    ABI_VERSION
}

/// NUL-terminated, static backend id.
#[no_mangle]
pub extern "C" fn hqargon2_backend_id() -> *const c_char {
    BACKEND_ID.as_ptr().cast()
}

/// Argon2id v0x13 (no secret, no associated data) of `pwd[0..pwd_len]` and
/// `salt[0..salt_len]` into `out[0..out_len]`, at `m_cost_kib` KiB of memory,
/// `t_cost` passes and `p_cost` lanes.
///
/// Returns 0, or a negative [`Error`] code with `out` zeroed. Blocks the
/// calling thread until done.
///
/// # Safety
/// `salt` and `out` must be valid for `salt_len` and `out_len` bytes, `out`
/// writable and not overlapping the inputs. `pwd` must be valid for `pwd_len`
/// bytes, or may be null when `pwd_len` is 0.
#[no_mangle]
pub unsafe extern "C" fn hqargon2id_derive(
    pwd: *const u8,
    pwd_len: usize,
    salt: *const u8,
    salt_len: usize,
    m_cost_kib: u32,
    t_cost: u32,
    p_cost: u32,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if out.is_null() {
        return Error::NullPointer as i32;
    }
    let out = std::slice::from_raw_parts_mut(out, out_len);
    if salt.is_null() || (pwd.is_null() && pwd_len != 0) {
        out.zeroize();
        return Error::NullPointer as i32;
    }
    let pwd: &[u8] = if pwd_len == 0 {
        &[]
    } else {
        std::slice::from_raw_parts(pwd, pwd_len)
    };
    let salt = std::slice::from_raw_parts(salt, salt_len);
    let result = catch_unwind(AssertUnwindSafe(|| {
        derive(pwd, salt, m_cost_kib, t_cost, p_cost, &mut *out)
    }));
    match result {
        Ok(Ok(())) => 0,
        Ok(Err(e)) => {
            out.zeroize();
            e as i32
        }
        Err(_) => {
            out.zeroize();
            Error::InternalPanic as i32
        }
    }
}
