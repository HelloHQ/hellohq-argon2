# Releasing

Push a tag `vX.Y.Z` to cut a release. `.github/workflows/release.yml` then:

1. runs the conformance gate;
2. builds every platform on GitHub-hosted runners;
3. writes `SHA256SUMS`;
4. attests build provenance for each asset;
5. publishes the GitHub Release.

## Steps

1. Bump `version` in `Cargo.toml`. The backend id follows it, and so do the
   tests that check it. Then run `cargo test --release`, commit and push `main`.
2. Wait until `ci.yml` is green. That covers the tests on every hosted OS, lint,
   cargo-deny, the pinned-Xcode check, the cross-checks and the determinism
   check.
3. Tag and push: `git tag vX.Y.Z && git push origin vX.Y.Z`. Then wait for
   `release.yml`.
4. Check the release. In an empty directory:
   - `gh release download vX.Y.Z --repo HelloHQ/hellohq-argon2`;
   - `sha256sum -c SHA256SUMS`;
   - for each asset,
     `gh attestation verify <asset> --repo HelloHQ/hellohq-argon2 --signer-workflow HelloHQ/hellohq-argon2/.github/workflows/release.yml`.
5. Pin the digests in the app: all of `VERSION`, `RELEASE_TAG` and every
   `SHA256_*` in hellohq's `native/argon2/artifacts.lock`, together, in one
   reviewed commit.

Never move a tag: the app pins the asset digests per tag.

## Toolchain and SDK pins

Every release build uses:

- the compiler in `rust-toolchain.toml`;
- the Xcode, SDKs, NDK and runner images pinned in
  `.github/workflows/_build.yml`.

A runner image that lacks a pinned Xcode or NDK fails the build; it never falls
back to what the image has. Move a pin deliberately: a new pin changes the bytes,
and so needs a new release and new digests in the app.
