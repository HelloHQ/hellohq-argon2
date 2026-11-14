//! Conformance and differential tests. A release is refused unless all pass
//! (`.github/workflows/release.yml`, conformance gate).

use hellohq_argon2::{derive, hqargon2_abi_version, hqargon2_backend_id, hqargon2id_derive, Error};

fn hex(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap()
}

fn ffi(pwd: &[u8], salt: &[u8], m: u32, t: u32, p: u32, out: &mut [u8]) -> i32 {
    unsafe {
        hqargon2id_derive(
            pwd.as_ptr(),
            pwd.len(),
            salt.as_ptr(),
            salt.len(),
            m,
            t,
            p,
            out.as_mut_ptr(),
            out.len(),
        )
    }
}

fn reference(pwd: &[u8], salt: &[u8], m: u32, t: u32, p: u32, len: usize) -> Vec<u8> {
    use ref_argon2::{Config, ThreadMode, Variant, Version};
    let config = Config {
        variant: Variant::Argon2id,
        version: Version::Version13,
        mem_cost: m,
        time_cost: t,
        lanes: p,
        thread_mode: ThreadMode::Sequential,
        secret: &[],
        ad: &[],
        hash_length: len as u32,
    };
    ref_argon2::hash_raw(pwd, salt, &config).unwrap()
}

/// RFC 9106 §5.3 (Argon2id, v0x13, m=32, t=3, p=4, secret and associated
/// data). The C ABI exposes neither, so this checks the dependency itself.
#[test]
fn rfc9106_argon2id_test_vector() {
    use argon2::{Algorithm, Argon2, Params, Version};
    let params = Params::new(32, 3, 4, Some(32)).unwrap();
    let secret = [3u8; 8];
    let ctx =
        Argon2::new_with_secret(&secret, Algorithm::Argon2id, Version::V0x13, params).unwrap();
    let mut out = [0u8; 32];
    let mut params_ad = argon2::ParamsBuilder::new();
    params_ad
        .m_cost(32)
        .t_cost(3)
        .p_cost(4)
        .output_len(32)
        .data(argon2::AssociatedData::new(&[4u8; 12]).unwrap());
    let ctx_ad = Argon2::new_with_secret(
        &secret,
        Algorithm::Argon2id,
        Version::V0x13,
        params_ad.build().unwrap(),
    )
    .unwrap();
    let mut mem = vec![argon2::Block::default(); 32];
    ctx_ad
        .hash_password_into_with_memory(&[1u8; 32], &[2u8; 16], &mut out, &mut mem[..])
        .unwrap();
    assert_eq!(
        hex::encode(out),
        "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659"
    );
    // Without associated data it must differ (the AD is really bound in).
    let mut other = [0u8; 32];
    ctx.hash_password_into_with_memory(&[1u8; 32], &[2u8; 16], &mut other, &mut mem[..])
        .unwrap();
    assert_ne!(out, other);
}

/// HelloHQ's Emergency Kit v2 known answer (EK-002, `kdf/argon2id-output`):
/// the production profile, 64 MiB, 3 passes, 4 lanes, 32-byte key.
#[test]
fn ek002_known_answer() {
    let pwd = hex(concat!(
        "68656c6c6f68713a656d657267656e63792d6b69743a6b64662d696e7075743a",
        "76320000120000000000000000000000000000000000000000000a2070617373",
        "776f726420"
    ));
    let salt = hex("000102030405060708090a0b0c0d0e0f");
    let mut out = [0u8; 32];
    assert_eq!(ffi(&pwd, &salt, 65536, 3, 4, &mut out), 0);
    assert_eq!(
        hex::encode(out),
        "a6d855ad9c9fdcea1a664a66806fb543a3f725e23d1797afec2084f6a611e77f"
    );
}

/// The cheap vector the app's loader derives once before it trusts the
/// library (`HellohqArgon2Native.load`). Frozen here and there.
pub const SELF_TEST_PASSWORD: &[u8] = b"hellohq-argon2 self-test";
pub const SELF_TEST_SALT: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
pub const SELF_TEST_OUTPUT: &str =
    "d4b6b0021a3986e5aab87ec1d9e9c4ed7409c00a544740ecca8f608c6bdea0b5";

#[test]
fn loader_self_test_vector() {
    let want = reference(SELF_TEST_PASSWORD, &SELF_TEST_SALT, 64, 1, 4, 32);
    let mut out = [0u8; 32];
    assert_eq!(
        ffi(SELF_TEST_PASSWORD, &SELF_TEST_SALT, 64, 1, 4, &mut out),
        0
    );
    assert_eq!(out.to_vec(), want);
    assert_eq!(hex::encode(out), SELF_TEST_OUTPUT);
}

/// Small deterministic PRNG (xorshift64*), so the differential cases are
/// reproducible without a rand dependency.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }
}

/// 400 random profiles, lengths and inputs against an independent
/// implementation (rust-argon2): lanes 1..=8, memory 8·p..8·p+2047 KiB,
/// passes 1..=4, output 4..=200 bytes (both sides of BLAKE2b's 64), passwords
/// 0..=299 bytes, salts 8..=64 bytes.
#[test]
fn differential_against_rust_argon2() {
    let mut r = Rng(0x48_51_41_52_47_4f_4e_32);
    for case in 0..400 {
        let p = 1 + r.below(8) as u32;
        let m = 8 * p + r.below(2048) as u32;
        let t = 1 + r.below(4) as u32;
        let len = 4 + r.below(197) as usize;
        let pwd = {
            let n = r.below(300) as usize;
            r.bytes(n)
        };
        let salt = {
            let n = 8 + r.below(57) as usize;
            r.bytes(n)
        };
        let want = reference(&pwd, &salt, m, t, p, len);
        let mut got = vec![0u8; len];
        assert_eq!(ffi(&pwd, &salt, m, t, p, &mut got), 0, "case {case}");
        assert_eq!(got, want, "case {case}: m={m} t={t} p={p} len={len}");
    }
}

/// The production profile against the independent implementation too.
#[test]
fn differential_production_profile() {
    let mut r = Rng(0x0123_4567_89ab_cdef);
    for case in 0..6 {
        let pwd = {
            let n = 1 + r.below(200) as usize;
            r.bytes(n)
        };
        let salt = {
            let n = 16 + r.below(17) as usize;
            r.bytes(n)
        };
        let want = reference(&pwd, &salt, 65536, 3, 4, 32);
        let mut got = [0u8; 32];
        assert_eq!(ffi(&pwd, &salt, 65536, 3, 4, &mut got), 0);
        assert_eq!(got.to_vec(), want, "case {case}");
    }
}

/// Several derivations at once from separate threads share the one rayon pool
/// and each still gets its own key.
#[test]
fn concurrent_derivations_are_independent() {
    let handles: Vec<_> = (0..8u8)
        .map(|i| {
            std::thread::spawn(move || {
                let salt = [i; 16];
                let mut out = [0u8; 32];
                assert_eq!(ffi(b"password", &salt, 4096, 2, 4, &mut out), 0);
                (out.to_vec(), reference(b"password", &salt, 4096, 2, 4, 32))
            })
        })
        .collect();
    for h in handles {
        let (got, want) = h.join().unwrap();
        assert_eq!(got, want);
    }
}

#[test]
fn errors_are_codes_and_zero_the_output() {
    let salt = [0u8; 16];
    /// (password, salt, memory KiB, passes, lanes, output length, expected error)
    type Case<'a> = (&'a [u8], &'a [u8], u32, u32, u32, usize, Error);
    let cases: [Case; 6] = [
        (b"pw", b"short", 64, 1, 1, 32, Error::BadLength), // salt < 8
        (b"pw", &salt, 64, 1, 1, 3, Error::BadLength),     // output < 4
        (b"pw", &salt, 31, 1, 4, 32, Error::BadParams),    // memory < 8 * lanes
        (b"pw", &salt, 64, 0, 1, 32, Error::BadParams),    // zero passes
        (b"pw", &salt, 64, 1, 0, 32, Error::BadParams),    // zero lanes
        (b"pw", &salt, 1 << 30, 1, 1 << 24, 32, Error::BadParams), // lanes > 2^24-1
    ];
    for (pwd, salt, m, t, p, len, want) in cases {
        let mut out = vec![0xAAu8; len];
        assert_eq!(ffi(pwd, salt, m, t, p, &mut out), want as i32, "{want:?}");
        assert!(out.iter().all(|&b| b == 0), "{want:?}: output not zeroed");
    }
    // Null pointers.
    let mut out = [0xAAu8; 32];
    let rc = unsafe {
        hqargon2id_derive(
            b"pw".as_ptr(),
            2,
            std::ptr::null(),
            16,
            64,
            1,
            1,
            out.as_mut_ptr(),
            32,
        )
    };
    assert_eq!(rc, Error::NullPointer as i32);
    assert_eq!(out, [0u8; 32]);
    let rc = unsafe {
        hqargon2id_derive(
            std::ptr::null(),
            2,
            salt.as_ptr(),
            16,
            64,
            1,
            1,
            out.as_mut_ptr(),
            32,
        )
    };
    assert_eq!(rc, Error::NullPointer as i32);
    let rc = unsafe {
        hqargon2id_derive(
            b"pw".as_ptr(),
            2,
            salt.as_ptr(),
            16,
            64,
            1,
            1,
            std::ptr::null_mut(),
            32,
        )
    };
    assert_eq!(rc, Error::NullPointer as i32);
    // An empty password with a null pointer is allowed.
    let mut out = [0u8; 32];
    let rc = unsafe {
        hqargon2id_derive(
            std::ptr::null(),
            0,
            salt.as_ptr(),
            16,
            64,
            1,
            1,
            out.as_mut_ptr(),
            32,
        )
    };
    assert_eq!(rc, 0);
    assert_eq!(out.to_vec(), reference(b"", &salt, 64, 1, 1, 32));
}

#[test]
fn abi_and_backend_id() {
    assert_eq!(hqargon2_abi_version(), 1);
    let id = unsafe { std::ffi::CStr::from_ptr(hqargon2_backend_id()) };
    assert_eq!(
        id.to_str().unwrap(),
        concat!(
            "hellohq-argon2 ",
            env!("CARGO_PKG_VERSION"),
            " (argon2 0.6.0 parallel)"
        )
    );
}

#[test]
fn derive_rejects_bad_output_length_before_work() {
    let mut out = [0u8; 2];
    assert_eq!(
        derive(b"pw", &[0u8; 16], 64, 1, 1, &mut out),
        Err(Error::BadLength)
    );
}
