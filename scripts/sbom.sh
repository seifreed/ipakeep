#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out="${1:-"$root/sbom/ipakeep.cdx.json"}"
repo="https://github.com/seifreed/ipakeep"
tmp="$(mktemp -d)"
raw="$root/.sbom-raw.json"
go_bom="$tmp/modern-anisette.cdx.json"
go_binary="$tmp/ipakeep-anisette-helper"
go_hashes="$tmp/go-module-hashes.tsv"
go_licenses="$tmp/go-module-licenses.tsv"
go_graph="$tmp/go-module-graph.txt"
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
        --spec-version 1.5 \
        --target all \
        --override-filename .sbom-raw
)

(
    cd "$root/tools/modern-anisette"
    GOOS=darwin GOARCH=arm64 go build -mod=readonly -trimpath -ldflags='-s -w' -o "$go_binary" .
    go run github.com/google/go-licenses/v2@v2.0.1 report ./...
) | awk -F, 'NF >= 3 { print $1 "\t" $3 "\t" $2 }' > "$go_licenses"
syft "file:$go_binary" -o cyclonedx-json > "$go_bom"
(cd "$root/tools/modern-anisette" && go mod graph) > "$go_graph"

# Go's h1 checksums are base64-encoded SHA-256 hashes of module file trees.
: > "$go_hashes"
while IFS=' ' read -r module version checksum; do
    [[ "$version" == */go.mod || "$checksum" != h1:* ]] && continue
    go_hash="$(printf '%s' "${checksum#h1:}" | openssl base64 -d -A | od -An -v -t x1 | tr -d ' \n')"
    printf '%s@%s\t%s\n' "$module" "$version" "$go_hash" >> "$go_hashes"
done < "$root/tools/modern-anisette/go.sum"

lib_hash="$(hash_file "$root/src/lib.rs")"
bin_hash="$(hash_file "$root/src/main.rs")"
lock_hash="$(hash_file "$root/Cargo.lock")"

jq \
    --arg repo "$repo" \
    --arg lib_hash "$lib_hash" \
    --arg bin_hash "$bin_hash" \
    --arg lock_hash "$lock_hash" \
    --slurpfile go_bom "$go_bom" \
    --rawfile go_hashes "$go_hashes" \
    --rawfile go_licenses "$go_licenses" \
    --rawfile go_graph "$go_graph" \
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
        if (.purl // "") | startswith("pkg:golang/") then
          (.purl | sub("^pkg:golang/"; "") | split("/") as $parts
            | if $parts[0] == "github.com" then $parts[1] else $parts[0] end)
        else
          ([.externalReferences[]? | select(.type == "vcs") | .url
            | try capture("^https?://(?<host>[^/]+)").host catch empty] | first)
        end
      );
    def add_supplier: .supplier = {name: supplier_name};
    def go_escape:
      [explode[] | if . >= 65 and . <= 90 then [33, . + 32] else [.] end]
      | flatten | implode;
    def go_hash_for($name; $version):
      (($name | go_escape) + "@" + $version) as $key
      | ($go_hashes | split("\n") | map(split("\t") | select(.[0] == $key) | .[1]) | first);
    def add_go_hash:
      if (.purl // "") | startswith("pkg:golang/") then
        go_hash_for(.name; .version) as $digest
        | if $digest then .hashes = [{alg: "SHA-256", content: $digest}] else . end
      else . end;
    def go_license_choices($name):
      if $name == "github.com/majd/ipatool/v2/ipakeep-anisette-helper" then
        [{license: {id: "MIT"}}]
      else
        [$go_licenses | split("\n")[] | split("\t")
          | select(.[0] == $name) | {id: .[1], url: .[2]}]
        | unique_by(.id)
        | map(
            if .id == "LGPL-3.0" then
              {license: {
                id: "LicenseRef-LGPL-3.0-with-Canonical-linking-exception",
                name: "LGPL-3.0 with Canonical linking exception",
                url: .url
              }}
            else
              {license: {id: .id, url: .url}}
            end
          )
      end;
    def add_go_licenses:
      if (.purl // "") | startswith("pkg:golang/") then
        go_license_choices(.name) as $choices
        | if ($choices | length) > 0 then .licenses = $choices else . end
      else . end;
    def go_components:
      ($go_bom[0].components // [])
      | group_by(.purl // ."bom-ref")
      | map(reduce .[] as $component ({}; . * $component));
    def go_root_name: "github.com/majd/ipatool/v2/ipakeep-anisette-helper";
    def go_root_version:
      [go_components[] | select(.name == go_root_name) | .version] | first;
    def go_component_ref($name; $version):
      [go_components[] | select(.name == $name and .version == $version) | ."bom-ref"] | first;
    def go_ref($module):
      ($module | split("@")) as $parts
      | if ($parts | length) == 1 then
          go_component_ref($parts[0]; go_root_version)
        else
          go_component_ref($parts[0]; ($parts[1:] | join("@")))
        end;
    def go_graph_edges:
      [$go_graph | split("\n")[] | split(" ") | select(length == 2)
        | {ref: go_ref(.[0]), dependency: go_ref(.[1])}
        | select(.ref != null and .dependency != null)]
      | group_by(.ref)
      | map({ref: .[0].ref, dependsOn: (map(.dependency) | unique)});
    def scrub_paths:
      if type == "object" then with_entries(.value |= scrub_paths)
      elif type == "array" then map(scrub_paths)
      elif type == "string" then
        gsub("path\\+file://[^#]+#0\\.1\\.0"; "pkg:cargo/ipakeep@0.1.0")
        | gsub("pkg:cargo/ipakeep@0\\.1\\.0\\?download_url=file://\\."; "pkg:cargo/ipakeep@0.1.0")
      else . end;

    scrub_paths
    | .components += (go_components | map(select(.name != "/go.mod") | add_go_hash | add_go_licenses))
    | (go_component_ref(go_root_name; go_root_version)) as $go_root_ref
    | .dependencies[0].dependsOn = ((.dependencies[0].dependsOn // []) + [$go_root_ref] | map(select(. != null)) | unique)
    | .dependencies += go_graph_edges
    | .dependencies |= (group_by(.ref) | map({ref: .[0].ref, dependsOn: (map(.dependsOn // []) | add | unique)}))
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
        if .name == "openssl-macros" then add_vcs("https://github.com/sfackler/rust-openssl") else . end
        | add_supplier
        | license_evidence
        | normalize_licenses
      )
    | .components |= (group_by(.purl // ."bom-ref") | map(reduce .[] as $component ({}; . * $component)))
    | (.dependencies[0].ref as $primary
      | .compositions = [{aggregate: "complete", dependencies: ([$primary] + .dependencies[0].dependsOn)}])
    ' "$raw" > "$out"

sbomqs score --configpath "$root/sbom/sbomqs-comprehensive.yaml" "$out"
sbomqs score --profile ntia "$out"
sbom-tools quality "$out" --profile comprehensive --recommendations
osv-scanner -L "$out"
grype "sbom:$out" --fail-on medium
