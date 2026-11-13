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

# libjailbreak's install name is @loader_path/libjailbreak.dylib, which would
# force our binary to sit next to a copy of the dylib. Repoint it at the
# device's absolute system path so dyld finds the real (trust-cached) one.
# Point at the REAL basebin path, not the /var/jb/usr/lib symlink: libjailbreak
# loads siblings (libchoma.dylib) via @loader_path, which must resolve to the
# directory that actually holds them (basebin), or dyld fails and AMFI kills us.
dev_libjb="/var/jb/basebin/libjailbreak.dylib"
if otool -L "$out" | grep -q '@loader_path/libjailbreak.dylib'; then
    install_name_tool -change @loader_path/libjailbreak.dylib "$dev_libjb" "$out"
    echo "build: repointed libjailbreak dependency to $dev_libjb"
fi

# Entitlements file is overridable (ENT=/path, or ENT= empty for none). A
# trust-cached binary already runs as a platform binary, so entitlements are
# often unnecessary; some restricted ones (platform-application) can even make
# AMFI reject an ad-hoc binary at exec.
ent="${ENT-$here/ent.plist}"
if command -v ldid >/dev/null 2>&1; then
    if [ -n "$ent" ] && [ -f "$ent" ]; then
        ldid -S"$ent" "$out"; echo "build: signed $out with ldid ($ent)"
    else
        ldid -S "$out"; echo "build: signed $out with ldid (no entitlements)"
    fi
else
    echo "build: ldid not found -- sign before running, e.g.:" >&2
    echo "  brew install ldid   # then: ldid -S'$here/ent.plist' '$out'" >&2
    echo "  or sign on the device with its own ldid." >&2
fi
