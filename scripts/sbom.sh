#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out="${1:-"$root/sbom/ipakeep.cdx.json"}"
repo="https://github.com/seifreed/ipakeep"
tmp="$(mktemp -d)"
raw="$root/.sbom-raw.json"
trap 'rm -rf "$tmp" "$raw"' EXIT

hash_file() {
    sha256sum "$1" | awk '{print $1}'
}

mkdir -p "$(dirname "$out")"

(
    cd "$tmp"
    SOURCE_DATE_EPOCH=0 cargo cyclonedx \
        --manifest-path "$root/Cargo.toml" \
        --format json \
        --spec-version 1.5 \
        --target all \
        --override-filename .sbom-raw
)

lib_hash="$(hash_file "$root/src/lib.rs")"
bin_hash="$(hash_file "$root/src/main.rs")"
lock_hash="$(hash_file "$root/Cargo.lock")"

jq \
    --arg repo "$repo" \
    --arg lib_hash "$lib_hash" \
    --arg bin_hash "$bin_hash" \
    --arg lock_hash "$lock_hash" \
    '
    def org($name): {name: $name, url: ["https://github.com/seifreed"]};
    def add_vcs($url):
      .externalReferences = ((.externalReferences // []) as $refs
        | if any($refs[]?; .type == "vcs") then $refs else $refs + [{type: "vcs", url: $url}] end);
    def license_evidence:
      if .licenses then .evidence.licenses = .licenses else . end;
    def normalize_license_expr:
      if .expression? then .expression |= gsub("/"; " OR ") else . end;
    def normalize_licenses:
      (if .licenses then .licenses |= map(normalize_license_expr) else . end)
      | (if .evidence.licenses then .evidence.licenses |= map(normalize_license_expr) else . end);
    def scrub_paths:
      if type == "object" then with_entries(.value |= scrub_paths)
      elif type == "array" then map(scrub_paths)
      elif type == "string" then
        gsub("path\\+file://[^#]+#0\\.1\\.0"; "pkg:cargo/ipakeep@0.1.0")
        | gsub("pkg:cargo/ipakeep@0\\.1\\.0\\?download_url=file://\\."; "pkg:cargo/ipakeep@0.1.0")
      else . end;

    scrub_paths
    | .serialNumber = "urn:uuid:7f60c5df-047a-5ac1-9a38-4f2f7d88c0a1"
    | .metadata.authors = [{name: "seifreed"}]
    | .metadata.supplier = org("seifreed")
    | .metadata.lifecycles = [{phase: "build"}]
    | .metadata.licenses = [{expression: "CC0-1.0"}]
    | .metadata.component |= (
        .supplier = org("seifreed")
        | .publisher = "seifreed"
        | .hashes = [{alg: "SHA-256", content: $lock_hash}]
        | add_vcs($repo)
        | license_evidence
        | normalize_licenses
      )
    | .metadata.component.components |= map(
        .supplier = org("seifreed")
        | .licenses = [{expression: "MIT"}]
        | .hashes = [{alg: "SHA-256", content: (if .type == "library" then $lib_hash else $bin_hash end)}]
        | add_vcs($repo)
        | license_evidence
        | normalize_licenses
      )
    | .components |= map(
        .supplier = {name: "NOASSERTION"}
        | license_evidence
        | normalize_licenses
        | if .name == "openssl-macros" then add_vcs("https://github.com/sfackler/rust-openssl") else . end
      )
    | (.dependencies[0].ref as $primary
      | .compositions = [{aggregate: "complete", dependencies: ([$primary] + .dependencies[0].dependsOn)}])
    ' "$raw" > "$out"

sbomqs score --configpath "$root/sbom/sbomqs-comprehensive.yaml" "$out"
sbomqs score --profile ntia "$out"
osv-scanner -L "$out"
grype "sbom:$out" --fail-on medium
