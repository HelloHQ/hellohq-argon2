# hellohq-argon2

Argon2id (RFC 9106, version 0x13) behind a small, explicit C ABI: a thin,
panic-safe, zeroizing wrapper around RustCrypto's
[`argon2`](https://crates.io/crates/argon2) 0.6.0, built for every platform the
HelloHQ app ships on and loaded there through `dart:ffi`.

The app derives its password keys with it: vault creation and unlock, Emergency
Kit v2, device database keys, offline exports and estate recovery kits. It
replaces package:cryptography's pure-Dart `DartArgon2id` as the runtime path.
That implementation stays in the app as the independent reference: the Emergency
Kit verifier uses it, and the app's tests compare this library against it.

## C ABI

```c
uint32_t    hqargon2_abi_version(void);   // 1
const char *hqargon2_backend_id(void);    // "hellohq-argon2 0.1.1 (argon2 0.6.0 parallel)"
int32_t     hqargon2id_derive(const uint8_t *pwd, size_t pwd_len,
                              const uint8_t *salt, size_t salt_len,
                              uint32_t m_cost_kib, uint32_t t_cost, uint32_t p_cost,
                              uint8_t *out, size_t out_len);
```

`hqargon2id_derive` returns 0, or a negative code with `out` zeroed:

| Code | Meaning |
|---|---|
| −1 | a required pointer was null (`pwd` may be null when `pwd_len` is 0) |
| −2 | a cost parameter is outside RFC 9106's limits (memory below 8 KiB per lane, zero passes, lanes outside 1..2²⁴−1) |
| −3 | salt shorter than 8 bytes, or output outside 4..2³²−1 bytes |
| −4 | the block matrix could not be mapped |
| −5 | an internal panic, caught at the boundary |

There is no secret and no associated data, because no HelloHQ derivation uses
either. The cost is always the caller's: the library has no default and no cap.
The app enforces its own policy, including the largest cost it accepts from a
stored envelope.

The call blocks the calling thread until the key is derived, so call it from a
background thread or isolate. The lanes of each slice run on rayon's process-wide
pool, with one thread per logical CPU, started on first use. Concurrent calls
share that pool. There is no timeout anywhere.

## Memory

The block matrix (64 MiB at HelloHQ's production cost) is an anonymous private
mapping that this library owns. It is wiped and then unmapped before the call
returns, so the pages go back to the OS at once. With the crate's own
allocation, freed through malloc, macOS kept them resident. See `SECURITY.md`
for what is and is not wiped.

## Assets

Releases are built by `.github/workflows/release.yml` on GitHub-hosted runners,
with build-provenance attestation.

| Asset | Platform |
|---|---|
| `libhellohq_argon2.dylib` | macOS universal (arm64 + x86_64), ad hoc signed; the app re-signs it with Developer ID |
| `HellohqArgon2.xcframework.zip` | iOS device + simulator (dynamic, with dSYMs) |
| `jniLibs.zip` | Android arm64-v8a, armeabi-v7a, x86_64, x86 (NDK API 21) |
| `libhellohq_argon2-linux-x64.so` | Linux x86_64 |
| `hellohq_argon2-windows-x64.dll` | Windows x86_64 |

## Tests

Run them with `cargo test --release`. They cover:

- **RFC 9106 §5.3** Argon2id, through the crate API, since the vector needs a
  secret and associated data.
- **EK-002**, HelloHQ's Emergency Kit v2 known answer at the production cost.
- **The loader self-test vector** that the app derives before it trusts the
  library.
- **400 random profiles plus 6 at the production cost**, checked against an
  independent implementation (`rust-argon2`, a dev-dependency only).
- **Concurrent derivations** from 8 threads.
- **Every error path**, each with its output zeroed.

## Reproducibility

Everything that changes the shipped bytes is pinned:

- rustc, in `rust-toolchain.toml`;
- Xcode, the macOS and iOS SDKs, the Android NDK and the runner images, in
  `_build.yml`;
- crates, in `Cargo.lock`, built with `--locked`.

Builds remap absolute paths, pin `SOURCE_DATE_EPOCH`, link MSVC with `/Brepro`
and sort the xcframework's `Info.plist`.

CI builds twice on each OS and compares the results. `reproduce.yml` rebuilds a
published tag and compares it with that tag's `SHA256SUMS`.

## Licence

MIT OR Apache-2.0.
