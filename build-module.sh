#!/usr/bin/env bash
# Builds the flashable root-helper zip: wingsvd for both ABIs plus the module scripts.
#
# Needs: rustup targets aarch64-linux-android + armv7-linux-androideabi, cargo-ndk, and
# an NDK. The NDK is taken from ANDROID_NDK_HOME, else ANDROID_HOME/ANDROID_SDK_ROOT,
# else the sdk.dir of the WINGS V checkout when this repo sits inside it as a submodule.
#
# Usage: ./build-module.sh [outdir]   (default: dist/ beside this script)
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
OUTDIR="$(cd "${1:-$HERE/dist}" 2>/dev/null && pwd || { mkdir -p "${1:-$HERE/dist}" && cd "${1:-$HERE/dist}" && pwd; })"
PLATFORM=29

if [ -z "${ANDROID_NDK_HOME:-}" ]; then
  sdk="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}"
  # As a submodule the checkout lives at <app>/external/WINGSV_Magisk, so the app's
  # local.properties is two levels up; standalone this simply finds nothing.
  [ -n "$sdk" ] || sdk="$(sed -n 's/^sdk.dir=//p' "$HERE/../../local.properties" 2>/dev/null || true)"
  # Highest-named NDK, matching how the upstream-runtime task picks one.
  ANDROID_NDK_HOME="$(ls -d "$sdk"/ndk/* 2>/dev/null | sort | tail -1)"
fi
[ -n "${ANDROID_NDK_HOME:-}" ] && [ -d "$ANDROID_NDK_HOME" ] || {
  echo "no NDK found: set ANDROID_NDK_HOME" >&2
  exit 1
}
export ANDROID_NDK_HOME
export ANDROID_NDK_ROOT="$ANDROID_NDK_HOME"

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

for pair in "arm64-v8a:aarch64-linux-android" "armeabi-v7a:armv7-linux-androideabi"; do
  abi="${pair%%:*}"
  target="${pair##*:}"
  echo "building wingsvd for $abi"
  (cd "$HERE/wingsvd" && cargo ndk --target "$abi" --platform "$PLATFORM" build --locked --release --bin wingsvd)
  binary="$HERE/wingsvd/target/$target/release/wingsvd"
  [ -f "$binary" ] || {
    echo "missing $binary" >&2
    exit 1
  }
  mkdir -p "$STAGE/bin/$abi"
  cp "$binary" "$STAGE/bin/$abi/wingsvd"
  chmod 755 "$STAGE/bin/$abi/wingsvd"
done

cp "$HERE/module.prop" "$HERE/service.sh" "$HERE/uninstall.sh" "$HERE/customize.sh" "$STAGE/"
chmod 755 "$STAGE/service.sh" "$STAGE/uninstall.sh" "$STAGE/customize.sh"

mkdir -p "$OUTDIR"
ZIP="$OUTDIR/wingsv-root-module.zip"
rm -f "$ZIP"
# -X: no extra file attributes, so the same input produces the same zip.
(cd "$STAGE" && zip -qrX "$ZIP" .)
echo "module: $ZIP"
