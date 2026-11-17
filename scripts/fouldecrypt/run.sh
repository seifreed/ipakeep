#!/bin/sh
# ipakeep FoulDecrypt device-side runner.
#
# Decrypts an installed app's Mach-O slices ON DISK with FoulDecrypt
# (mremap_encrypted + kernel R/W), WITHOUT launching the app, then repackages
# the decrypted bundle into an IPA. Runs on a jailbroken device over SSH.
#
# Usage: run.sh <bundle-id> <out-ipa-path>
set -eu

if [ "$#" -ne 2 ]; then
    echo "ipakeep: usage: run.sh <bundle-id> <out-ipa-path>" >&2
    exit 2
fi

bundle_id="$1"
out_ipa="$2"

foulwrapper="$(command -v foulwrapper 2>/dev/null || true)"
fouldecrypt="$(command -v fouldecrypt 2>/dev/null || true)"
if [ -z "$foulwrapper" ] && [ -z "$fouldecrypt" ]; then
    echo "ipakeep: FoulDecrypt not found on device (need 'fouldecrypt' or 'foulwrapper' on PATH)." >&2
    echo "ipakeep: install FoulDecrypt (https://github.com/NyaMisty/fouldecrypt) from its Cydia/Sileo repo." >&2
    echo "ipakeep: it requires a jailbreak with kernel R/W (libkrw / libkernrw)." >&2
    exit 3
fi
if ! command -v zip >/dev/null 2>&1; then
    echo "ipakeep: 'zip' not found on device; install it (e.g. the 'zip' package) to repackage the IPA." >&2
    exit 5
fi

# Locate the installed .app declaring this bundle id. Match by scanning the
# Info.plist for the id itself: this works for both XML and binary plists and
# needs no plutil. The rootless-jailbreak `plutil` package is a minimal clone
# that lacks Apple's -extract/-p, so parsing the key out is not portable; the
# id is the argument we already know, so a literal match is enough.
# ponytail: a reverse-DNS id is effectively unique across distinct apps, and
# extensions are *.appex nested inside the .app (never matched here), so the
# first *.app whose plist contains the id is the right bundle.
app="$(
    find /var/containers/Bundle/Application -maxdepth 3 -name '*.app' 2>/dev/null |
        while IFS= read -r candidate; do
            if grep -qaF "$bundle_id" "$candidate/Info.plist" 2>/dev/null; then
                printf '%s\n' "$candidate"
                break
            fi
        done
)"
if [ -z "$app" ]; then
    echo "ipakeep: no installed .app with bundle id '$bundle_id' under /var/containers/Bundle/Application." >&2
    exit 4
fi

work="$(mktemp -d "${TMPDIR:-/tmp}/ipakeep-foul.XXXXXX")"
trap 'rm -rf "$work"' EXIT INT TERM

appname="$(basename "$app")"
payload="$work/Payload"
mkdir -p "$payload"
cp -a "$app" "$payload/$appname"
staged="$payload/$appname"

is_macho() {
    case "$(od -An -tx1 -N4 "$1" 2>/dev/null | tr -d ' \n')" in
        cffaedfe|cefaedfe|cafebabe|bebafeca|feedface|cffeedfa) return 0 ;;
        *) return 1 ;;
    esac
}

if [ -n "$foulwrapper" ]; then
    # foulwrapper decrypts every Mach-O inside the .app in place.
    "$foulwrapper" "$staged" >&2
else
    # fouldecrypt handles one Mach-O at a time: walk the staged bundle and
    # decrypt each Mach-O file in place.
    find "$staged" -type f 2>/dev/null | while IFS= read -r f; do
        if is_macho "$f"; then
            "$fouldecrypt" "$f" "$f" >&2 || true
        fi
    done
fi

rm -f "$out_ipa"
( cd "$work" && zip -qry "$out_ipa" Payload )
echo "$out_ipa"
