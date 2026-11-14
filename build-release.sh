#!/usr/bin/env bash
# Build the Argon2id native libs for the CURRENT host's platforms and stage
# them (+ SHA256SUMS) for the release pipeline (.github/workflows/release.yml).
#
#   macOS   -> libhellohq_argon2.dylib (universal arm64+x86_64)
#              HellohqArgon2.xcframework.zip (iOS device + simulator, dynamic)
#   Linux   -> libhellohq_argon2-linux-x64.so / -linux-arm64.so
#              jniLibs.zip (Android arm64-v8a, armeabi-v7a, x86_64, x86) when
#              ANDROID_NDK_HOME is set (the NDK's clang links each ABI)
#   Windows -> hellohq_argon2-windows-x64.dll (-windows-arm64.dll with HQ_WINDOWS_ARM64=1)
#
# Deterministic-build settings: --locked (Cargo.lock is authoritative),
# absolute build paths remapped out of the binary, SOURCE_DATE_EPOCH pinned to the commit time, /Brepro on MSVC, a sorted
# xcframework Info.plist.
set -euo pipefail

CRATE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STAGE="${1:-$CRATE_DIR/dist}"
cd "$CRATE_DIR"
rm -rf "$STAGE" && mkdir -p "$STAGE"
STAGE="$(cd "$STAGE" && pwd)" # xcodebuild -debug-symbols needs an absolute path

export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct 2>/dev/null || echo 0)}"
CARGO_HOME_DIR="${CARGO_HOME:-$HOME/.cargo}"
export RUSTFLAGS="${RUSTFLAGS:-} --remap-path-prefix=$CRATE_DIR=/build --remap-path-prefix=$CARGO_HOME_DIR=/cargo --remap-path-prefix=$HOME=/home"

build() { echo "-> cargo build --release --locked --target $1"; cargo build --release --locked --target "$1"; }

# iOS slices also get a dSYM: App Store Connect symbolicates crash reports with
# it, matched by Mach-O UUID, so it can only come from the build that produced
# the shipped binary. `split-debuginfo = packed` makes rustc run dsymutil before
# `strip = true`, so the dylib ships stripped as before and the debug info
# (line tables and function names, no variables) goes to <dylib>.dSYM.
build_ios() {
  echo "-> cargo build --release --locked --target $1 (+ dSYM)"
  CARGO_PROFILE_RELEASE_DEBUG=limited CARGO_PROFILE_RELEASE_SPLIT_DEBUGINFO=packed \
    cargo build --release --locked --target "$1"
}

# ios_dsym <out.dSYM> <target>...: the dSYM for one xcframework slice, lipo'd
# across that slice's targets. dsym_matches refuses one whose UUIDs differ.
ios_dsym() {
  local out="$1" dwarf="Contents/Resources/DWARF/libhellohq_argon2.dylib" t parts=()
  shift
  cp -RL "target/$1/release/libhellohq_argon2.dylib.dSYM" "$out"
  for t in "$@"; do parts+=("target/$t/release/libhellohq_argon2.dylib.dSYM/$dwarf"); done
  [ "$#" -eq 1 ] || lipo -create "${parts[@]}" -output "$out/$dwarf"
}
dsym_matches() { # dsym_matches <dylib> <dSYM>
  [ "$(dwarfdump --uuid "$1" | awk '{print $2, $3}' | sort)" = \
    "$(dwarfdump --uuid "$2" | awk '{print $2, $3}' | sort)" ] \
    || { echo "::error::$2 does not match the UUIDs of $1"; dwarfdump --uuid "$1" "$2"; exit 1; }
}

# Android: cargo with the NDK's clang as linker for each ABI, which is what
# cargo-ndk would do, without installing it. API level 21, cargo-ndk's default.
ANDROID_API=21
build_android() {
  if [ -z "${ANDROID_NDK_HOME:-}" ]; then
    echo "WARN: ANDROID_NDK_HOME not set; skipping Android"; return 0
  fi
  local bin abi triple clang
  bin="$(echo "$ANDROID_NDK_HOME"/toolchains/llvm/prebuilt/*/bin)"
  [ -x "$bin/llvm-ar" ] || { echo "::error::no NDK llvm toolchain under $ANDROID_NDK_HOME"; exit 1; }
  echo "-> cargo build -> jniLibs (arm64-v8a, armeabi-v7a, x86_64, x86), NDK API $ANDROID_API"
  for pair in arm64-v8a:aarch64-linux-android:aarch64-linux-android \
              armeabi-v7a:armv7-linux-androideabi:armv7a-linux-androideabi \
              x86_64:x86_64-linux-android:x86_64-linux-android \
              x86:i686-linux-android:i686-linux-android; do
    IFS=: read -r abi triple clang <<<"$pair"
    local up; up="$(echo "$triple" | tr 'a-z-' 'A-Z_')"
    # 16 KB pages: Android 15+ devices with 16 KB pages refuse a library whose
    # LOAD segments are only 4 KB-aligned, and Google Play requires 16 KB
    # support for apps targeting SDK 35+. NDK r28 aligns by default; the pinned
    # r27d does not, so ask the linker explicitly (harmless on 4 KB devices).
    env "CARGO_TARGET_${up}_LINKER=$bin/${clang}${ANDROID_API}-clang" \
        "CC_${triple//-/_}=$bin/${clang}${ANDROID_API}-clang" \
        "AR_${triple//-/_}=$bin/llvm-ar" \
        "RUSTFLAGS=$RUSTFLAGS -C link-arg=-Wl,-z,max-page-size=16384" \
      cargo build --release --locked --target "$triple"
    mkdir -p "$STAGE/jniLibs/$abi"
    cp "target/$triple/release/libhellohq_argon2.so" "$STAGE/jniLibs/$abi/"
    # Fail closed: every LOAD segment of every ABI must be aligned to >= 16 KB.
    local aligns bad
    aligns="$("$bin/llvm-readelf" -lW "$STAGE/jniLibs/$abi/libhellohq_argon2.so" | awk '$1 == "LOAD" {print $NF}')"
    [ -n "$aligns" ] || { echo "::error::$abi: no LOAD segments read"; exit 1; }
    bad="$(echo "$aligns" | while read -r a; do [ $((a)) -ge 16384 ] || echo "$a"; done)"
    [ -z "$bad" ] || { echo "::error::$abi libhellohq_argon2.so has LOAD segments aligned to $bad (< 16 KB)"; exit 1; }
    echo "ok 16 KB-aligned LOAD segments: $abi"
  done
  find "$STAGE/jniLibs" -exec touch -t 200001010000 {} +
  ( cd "$STAGE" && find jniLibs | LC_ALL=C sort | zip -qX -@ jniLibs.zip && rm -rf jniLibs )
}

case "$(uname -s)" in
  Darwin)
    for t in aarch64-apple-darwin x86_64-apple-darwin; do build "$t"; done
    for t in aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios; do build_ios "$t"; done
    # Same install name for every slice so the Dart loader and the app bundle
    # resolve the library identically (@rpath), like HellohqMlkem and MldsaVerify.
    lipo -create \
      target/aarch64-apple-darwin/release/libhellohq_argon2.dylib \
      target/x86_64-apple-darwin/release/libhellohq_argon2.dylib \
      -output "$STAGE/libhellohq_argon2.dylib"
    install_name_tool -id @rpath/libhellohq_argon2.dylib "$STAGE/libhellohq_argon2.dylib"
    # Re-sign ad hoc after install_name_tool invalidated the linker signature.
    codesign --force --sign - "$STAGE/libhellohq_argon2.dylib"

    DEV="$STAGE/_iosdev"; SIM="$STAGE/_iossim"; mkdir -p "$DEV" "$SIM"
    cp target/aarch64-apple-ios/release/libhellohq_argon2.dylib "$DEV/libhellohq_argon2.dylib"
    lipo -create \
      target/aarch64-apple-ios-sim/release/libhellohq_argon2.dylib \
      target/x86_64-apple-ios/release/libhellohq_argon2.dylib \
      -output "$SIM/libhellohq_argon2.dylib"
    for d in "$DEV" "$SIM"; do
      install_name_tool -id @rpath/libhellohq_argon2.dylib "$d/libhellohq_argon2.dylib"
      codesign --force --sign - "$d/libhellohq_argon2.dylib"
    done
    # install_name_tool and codesign leave LC_UUID alone, so the dSYMs still
    # match; checked anyway, since a mismatched dSYM is silently useless.
    ios_dsym "$DEV/libhellohq_argon2.dylib.dSYM" aarch64-apple-ios
    ios_dsym "$SIM/libhellohq_argon2.dylib.dSYM" aarch64-apple-ios-sim x86_64-apple-ios
    for d in "$DEV" "$SIM"; do dsym_matches "$d/libhellohq_argon2.dylib" "$d/libhellohq_argon2.dylib.dSYM"; done
    rm -rf "$STAGE/HellohqArgon2.xcframework"
    # -debug-symbols puts each slice's dSYM in <slice>/dSYMs, where Xcode finds
    # it and copies it into the app archive. It needs an absolute path.
    xcodebuild -create-xcframework \
      -library "$DEV/libhellohq_argon2.dylib" -debug-symbols "$DEV/libhellohq_argon2.dylib.dSYM" \
      -library "$SIM/libhellohq_argon2.dylib" -debug-symbols "$SIM/libhellohq_argon2.dylib.dSYM" \
      -output "$STAGE/HellohqArgon2.xcframework"
    rm -rf "$DEV" "$SIM"
    # xcodebuild lists AvailableLibraries in a nondeterministic order (two
    # clean builds on one machine gave both orders), so sort them by
    # LibraryIdentifier. plistlib writes the same XML layout as xcodebuild:
    # with the slices in this order two builds give the same file.
    python3 - "$STAGE/HellohqArgon2.xcframework/Info.plist" <<'PY'
import plistlib
import sys

path = sys.argv[1]
with open(path, "rb") as f:
    info = plistlib.load(f)
info["AvailableLibraries"].sort(key=lambda lib: lib["LibraryIdentifier"])
with open(path, "wb") as f:
    plistlib.dump(info, f, fmt=plistlib.FMT_XML, sort_keys=True)
PY
    # Fixed mtimes + sorted entries so the zip bytes are reproducible.
    find "$STAGE/HellohqArgon2.xcframework" -exec touch -t 200001010000 {} +
    ( cd "$STAGE" && find HellohqArgon2.xcframework | LC_ALL=C sort | zip -qX -@ HellohqArgon2.xcframework.zip && rm -rf HellohqArgon2.xcframework )
    ;;
  Linux)
    # One native build per runner architecture: x86_64 runner -> linux-x64 (+
    # Android jniLibs), aarch64 runner -> linux-arm64. No cross-linkers needed.
    case "$(uname -m)" in
      x86_64)
        build x86_64-unknown-linux-gnu
        cp target/x86_64-unknown-linux-gnu/release/libhellohq_argon2.so "$STAGE/libhellohq_argon2-linux-x64.so"
        [ -n "${ANDROID_NDK_HOME:-}" ] && build_android || true
        ;;
      aarch64|arm64)
        build aarch64-unknown-linux-gnu
        cp target/aarch64-unknown-linux-gnu/release/libhellohq_argon2.so "$STAGE/libhellohq_argon2-linux-arm64.so"
        ;;
      *) echo "::error::unsupported Linux arch $(uname -m)"; exit 1 ;;
    esac
    ;;
  MINGW*|MSYS*|CYGWIN*|Windows_NT)
    # /Brepro: link.exe otherwise stamps the wall-clock link time into the PE
    # header (TimeDateStamp) and a random PDB GUID into the debug directory, so
    # no two builds match.
    export RUSTFLAGS="$RUSTFLAGS -C link-arg=/Brepro"
    build x86_64-pc-windows-msvc
    cp target/x86_64-pc-windows-msvc/release/hellohq_argon2.dll "$STAGE/hellohq_argon2-windows-x64.dll"
    # Windows ARM64 is not released: no HelloHQ app build ships it.
    # HQ_WINDOWS_ARM64=1 builds it where an MSVC ARM64 linker is installed.
    if [ "${HQ_WINDOWS_ARM64:-0}" = 1 ]; then
      build aarch64-pc-windows-msvc
      cp target/aarch64-pc-windows-msvc/release/hellohq_argon2.dll "$STAGE/hellohq_argon2-windows-arm64.dll"
    fi
    ;;
esac

( cd "$STAGE" && { shasum -a 256 * 2>/dev/null || sha256sum *; } > ../SHA256SUMS.tmp && mv ../SHA256SUMS.tmp SHA256SUMS )
echo "Staged for $(uname -s):" && ls -1 "$STAGE"
