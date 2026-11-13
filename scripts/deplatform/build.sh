#!/bin/sh
# Build an ipakeep de-platform tool for an arm64 (A11+) iOS device.
#
# Usage: build.sh <source.c> [out-binary]
#   e.g. build.sh deplatform_probe.c deplatform_probe
#
# Cross-compiles on macOS with the iPhoneOS SDK and links the device's
# libjailbreak (Dopamine/BaseBin). Because libjailbreak is not public, copy it
# off the device first (or point LIBJAILBREAK at it):
#   scp mobile@DEVICE:/var/jb/usr/lib/libjailbreak.dylib scripts/deplatform/
#
# The result is ad-hoc signed. To RUN it on a Dopamine device it must be in the
# trust cache (this makes it a platform binary -- which is exactly the status
# the de-platform helper then clears on itself at runtime):
#   scp <out> mobile@DEVICE:/var/mobile/
#   ssh ... 'sudo jbctl trustcache add /var/mobile/<out> && /var/mobile/<out>'
set -eu

here="$(cd "$(dirname "$0")" && pwd)"
src="${1:?usage: build.sh <source.c> [out]}"
out="${2:-$(basename "$src" .c)}"

sdk="$(xcrun --sdk iphoneos --show-sdk-path 2>/dev/null)" || {
    echo "build: no iPhoneOS SDK (install Xcode + 'xcode-select --install')." >&2
    exit 1
}

libjb="${LIBJAILBREAK:-$here/libjailbreak.dylib}"
if [ ! -f "$libjb" ]; then
    echo "build: libjailbreak.dylib not found at '$libjb'." >&2
    echo "build: copy it off the device:" >&2
    echo "  scp mobile@DEVICE:/var/jb/usr/lib/libjailbreak.dylib '$here/'" >&2
    echo "build: or set LIBJAILBREAK=/path/to/libjailbreak.dylib." >&2
    exit 1
fi

cc="$(xcrun --sdk iphoneos --find clang)"
"$cc" -arch arm64 -isysroot "$sdk" -miphoneos-version-min=16.0 \
    -Wall -Wextra -O2 \
    -I"$here" \
    "$src" "$libjb" \
    -o "$out"
echo "build: compiled $out"

if command -v ldid >/dev/null 2>&1; then
    ldid -S"$here/ent.plist" "$out"
    echo "build: signed $out with ldid (ent.plist)"
else
    echo "build: ldid not found -- sign before running, e.g.:" >&2
    echo "  brew install ldid   # then: ldid -S'$here/ent.plist' '$out'" >&2
    echo "  or sign on the device with its own ldid." >&2
fi
