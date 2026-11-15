#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out="${1:-"$root/sbom/ipakeep.cdx.json"}"
repo="https://github.com/seifreed/ipakeep"
tmp="$(mktemp -d)"
raw="$root/.sbom-raw.json"
candidate="$tmp/ipakeep.cdx.json"
trap 'rm -rf "$tmp" "$raw"' EXIT

hash_file() {
    sha256sum "$1" | awk '{print $1}'
}

mkdir -p "$(dirname "$out")"

(
    cd "$tmp"
    SOURCE_DATE_EPOCH="$(date -u +%s)" cargo cyclonedx \
        --manifest-path "$root/Cargo.toml" \
        --format json \
        --spec-version 1.7 \
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
    --arg contact_email "mriverolopez@gmail.com" \
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
    def github_owner:
      [.externalReferences[]? | select(.type == "vcs") | .url
        | try capture("^https?://github\\.com/(?<owner>[^/]+)").owner catch empty]
      | first;
    def supplier_name:
      github_owner // (
        [.externalReferences[]? | select(.type == "vcs") | .url
          | try capture("^https?://(?<host>[^/]+)").host catch empty] | first
      );
    def add_supplier: .supplier = {name: supplier_name};
    def scrub_paths:
      if type == "object" then
        . as $original
        | with_entries(.value |= scrub_paths)
        | if ($original.purl // "") | startswith("pkg:cargo/ipakeep@") then
            .purl |= sub("\\?download_url=file://\\."; "")
            | if ($original["bom-ref"] // "") | startswith("path+file://") then .["bom-ref"] = .purl else . end
          else . end
      elif type == "array" then map(scrub_paths)
      elif type == "string" then
        gsub("path\\+file://[^#]+#(ipakeep@)?(?<version>[0-9]+\\.[0-9]+\\.[0-9]+)(?<target> bin-target-[0-9]+)?"; "pkg:cargo/ipakeep@\(.version)\(.target // "")")
      else . end;

    scrub_paths
    | .dependencies |= (group_by(.ref) | map({ref: .[0].ref, dependsOn: (map(.dependsOn // []) | add | unique)}))
    | .serialNumber = "urn:uuid:7f60c5df-047a-5ac1-9a38-4f2f7d88c0a1"
    | .citations = [
        {"bom-ref": "cargo-lock-source", pointers: ["/components", "/dependencies"], timestamp: .metadata.timestamp, attributedTo: .metadata.component."bom-ref", note: "Rust dependency inventory derived from Cargo.lock."}
      ]
    | .metadata.authors = [{name: "seifreed", email: $contact_email}]
    | .metadata.supplier = org("seifreed")
    | .metadata.lifecycles = [{phase: "build"}]
    | .metadata.licenses = [{expression: "CC0-1.0"}]
    | .metadata.component |= (
        .supplier = org("seifreed")
        | .publisher = "seifreed"
        | .hashes = [{alg: "SHA-256", content: $lock_hash}]
        | .externalReferences = ((.externalReferences // []) + [
            {type: "security-contact", url: ("mailto:" + $contact_email)},
            {type: "advisories", url: "https://github.com/seifreed/ipakeep/security/advisories/new"}
          ] | unique_by([.type, .url]))
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
        add_supplier
        | license_evidence
        | normalize_licenses
      )
    | .components |= (group_by(.purl // ."bom-ref") | map(reduce .[] as $component ({}; . * $component)))
    | (.dependencies[0].ref as $primary
      | .compositions = [{aggregate: "complete", dependencies: ([$primary] + .dependencies[0].dependsOn)}])
    ' "$raw" > "$candidate"

jq -e '
  .specVersion == "1.7"
  and ([.. | strings | select(test("path\\+file://|file://|/Users/"))] | length == 0)
  and ([.. | objects | ."bom-ref"? // empty] as $refs | ($refs | length) == ($refs | unique | length))
  and ([.components[] | select((.purl // "") | startswith("pkg:golang/"))] | length == 0)
' "$candidate" > /dev/null
sbomqs score --configpath "$root/sbom/sbomqs-comprehensive.yaml" "$candidate"
sbomqs score --profile ntia "$candidate"
sbom-tools quality "$candidate" --profile comprehensive --recommendations
osv-scanner -L "$candidate"
grype "sbom:$candidate" --fail-on medium
mv "$candidate" "$out"
