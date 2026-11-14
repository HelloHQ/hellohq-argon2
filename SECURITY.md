# Security

Report security issues privately through GitHub Security Advisories on this
repository, not as a public issue.

## What this library guarantees

- **Algorithm.** Argon2id, version 0x13, exactly as RFC 9106 specifies it,
  through RustCrypto `argon2` 0.6.0. The RFC 9106 test vector, HelloHQ's EK-002
  known answer, and a differential test against an independent implementation
  run before every release.
- **No undefined behaviour at the boundary.**
  - Every buffer has an explicit length.
  - Null pointers are rejected.
  - A panic is caught with `catch_unwind` and returned as an error code.
- **No garbage on failure.** On any error, `out` is zeroed before the call
  returns.
- **The block matrix is wiped.** The whole matrix is overwritten with zeroes
  (`zeroize`, which the compiler may not elide) and then unmapped, on success
  and on every error after it was mapped.
- **No secret outlives a call in memory this library allocated.**

## What it does not guarantee

- **Stack temporaries inside `argon2`.** The initial hash `H0`, its BLAKE2b
  state and the per-segment address and input blocks live on the stacks of the
  calling thread and the rayon workers. `argon2` wipes `H0` and the final block
  hash when its `zeroize` feature is on, as it is here; other temporaries are
  outside this crate's reach.
- **The caller's buffers.** The password, the salt and the output belong to the
  caller, who must wipe them. HelloHQ's Dart binding copies the password into
  native memory and wipes that copy after the call, but copies on the Dart heap
  are the garbage collector's.
- **Constant-time comparison.** Comparing derived keys is the caller's job.
  Argon2id itself uses data-dependent addressing after the first half of the
  first pass, by design.
- **Resource limits.** Memory, passes and lanes are the caller's. A caller that
  takes the cost from untrusted input must cap it first. Otherwise a large
  `m_cost_kib` makes the derivation map, and then touch, that much memory.
- **FIPS validation.** This is algorithm conformance, not a FIPS 140-3
  validated module.
