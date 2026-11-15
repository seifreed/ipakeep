#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out="${1:-"$root/sbom/ipakeep.cdx.json"}"
repo="https://github.com/seifreed/ipakeep"
tmp="$(mktemp -d)"
raw="$root/.sbom-raw.json"
go_bom="$tmp/modern-anisette.cdx.json"
go_binary="$tmp/ipakeep-anisette-helper"
go_toolchain="go$(awk '$1 == "go" { print $2; exit }' "$root/tools/modern-anisette/go.mod")"
go_binary_hash="$tmp/go-binary.sha256"
xz_license_file="$tmp/xz-LICENSE"
go_hashes="$tmp/go-module-hashes.tsv"
go_licenses="$tmp/go-module-licenses.tsv"
go_graph="$tmp/go-module-graph.txt"
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

(
    cd "$root/tools/modern-anisette"
    GOTOOLCHAIN="$go_toolchain" GOOS=darwin GOARCH=arm64 go build -mod=readonly -trimpath -ldflags='-s -w' -o "$go_binary" .
    GOTOOLCHAIN="$go_toolchain" go run github.com/google/go-licenses/v2@v2.0.1 report ./...
) | awk -F, 'NF >= 3 { print $1 "\t" $3 "\t" $2 }' > "$go_licenses"
syft "file:$go_binary" -o cyclonedx-json > "$go_bom"
hash_file "$go_binary" > "$go_binary_hash"
(cd "$root/tools/modern-anisette" && GOTOOLCHAIN="$go_toolchain" go mod graph) > "$go_graph"
xz_module_dir="$(cd "$root/tools/modern-anisette" && GOTOOLCHAIN="$go_toolchain" go list -m -f '{{.Dir}}' github.com/xi2/xz)"
cp "$xz_module_dir/LICENSE" "$xz_license_file"

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
go_binary_hash="$(cat "$go_binary_hash")"

jq \
    --arg repo "$repo" \
    --arg lib_hash "$lib_hash" \
    --arg bin_hash "$bin_hash" \
    --arg lock_hash "$lock_hash" \
    --arg go_binary_hash "$go_binary_hash" \
    --arg contact_email "mriverolopez@gmail.com" \
    --slurpfile go_bom "$go_bom" \
    --rawfile xz_license "$xz_license_file" \
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
    def go_hash_for($name; $version):
      ($name + "@" + $version) as $key
      | ($go_hashes | split("\n") | map(split("\t") | select(.[0] == $key) | .[1]) | first);
    def go_component_names: [$go_bom[0].components[]? | .name];
    def add_go_hash:
      if .name == "github.com/majd/ipatool/v2/ipakeep-anisette-helper" then
        .hashes = [{alg: "SHA-256", content: $go_binary_hash}]
      elif (.purl // "") | startswith("pkg:golang/") then
        go_hash_for(.name; .version) as $digest
        | if $digest then .hashes = [{alg: "SHA-256", content: $digest}] else . end
      else . end;
    def go_license_rows($name):
      [$go_licenses | split("\n")[] | split("\t") | select(length >= 3)
        | . as $row
        | select($row[0] == $name or ($row[0] | startswith($name + "/")))
        | select([go_component_names[] as $module
            | select($module != $name and ($module | startswith($name + "/"))
                and ($row[0] | startswith($module + "/")))] | length == 0)];
    def go_license_choices($name):
      if $name == "github.com/majd/ipatool/v2/ipakeep-anisette-helper" then
        [{license: {id: "MIT"}}]
      else
        [go_license_rows($name)[] | {id: .[1], url: .[2]}]
        | unique_by(.id)
        | map(
            if .id == "LGPL-3.0" then
              {license: {
                id: "LicenseRef-LGPL-3.0-with-Canonical-linking-exception",
                name: "LGPL-3.0 with Canonical linking exception",
                url: .url
              }}
            elif .id == "XZ" then
              {expression: "LicenseRef-XZ-Public-Domain",
                expressionDetails: [{
                  licenseIdentifier: "LicenseRef-XZ-Public-Domain",
                  url: .url,
                  text: {content: $xz_license}
                }]}
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
    def add_go_references:
      if (.purl // "") | startswith("pkg:golang/") then
        . as $component
        | .name as $name
        | [go_license_rows($name)[] | .[2] | select(startswith("http"))] | unique as $license_urls
        | ([go_license_rows($name)[] | .[2]
            | try capture("^https?://github\\.com/(?<repo>[^/]+/[^/]+)/blob/").repo catch empty
            | "https://github.com/" + .]
           + (if $name | startswith("golang.org/x/") then
                ["https://go.googlesource.com/" + ($name | split("/")[2:4] | join("/"))]
              else [] end))
          | unique as $vcs_urls
        | $component
        | .externalReferences = ((.externalReferences // [])
            + ($vcs_urls | map({type: "vcs", url: .}))
            + ($license_urls | map({type: "license", url: .}))
            + [{type: "website", url: (if $name == "stdlib" then "https://pkg.go.dev/std" else "https://pkg.go.dev/" + $name end)}]
            | unique_by([.type, .url]))
      else . end;
    def normalize_go_stdlib_version:
      if .name == "github.com/majd/ipatool/v2/ipakeep-anisette-helper" then
        .licenses = [{license: {id: "MIT"}}]
      elif .name == "github.com/majd/ipatool/v2" then
        .licenses |= map(select(.license.id != "Unknown"))
      elif .name == "stdlib" and ((.version // "") | startswith("go")) then
        .version |= sub("^go"; "")
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
    def go_stdlib_ref:
      [go_components[] | select(.name == "stdlib") | ."bom-ref"] | first;
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
      if type == "object" then
        . as $original
        | with_entries(.value |= scrub_paths)
        | if ($original.purl // "") | startswith("pkg:cargo/ipakeep@") then
            .purl |= sub("\\?download_url=file://\\."; "")
            | if ($original["bom-ref"] // "") | startswith("path+file://") then .["bom-ref"] = .purl else . end
          else . end
      elif type == "array" then map(scrub_paths)
      elif type == "string" then
        gsub("path\\+file://[^#]+#(?<version>[0-9]+\\.[0-9]+\\.[0-9]+)(?<target> bin-target-[0-9]+)?"; "pkg:cargo/ipakeep@\(.version)\(.target // "")")
      else . end;

    scrub_paths
    | .components += (go_components | map(select(.name != "/go.mod") | add_go_hash | add_go_licenses | add_go_references | normalize_go_stdlib_version))
    | (go_component_ref(go_root_name; go_root_version)) as $go_root_ref
    | (go_stdlib_ref) as $go_stdlib_ref
    | .dependencies[0].dependsOn = ((.dependencies[0].dependsOn // []) + [$go_root_ref] | map(select(. != null)) | unique)
    | .dependencies += go_graph_edges
    | .dependencies += [{ref: $go_root_ref, dependsOn: [$go_stdlib_ref]}]
    | .dependencies |= (group_by(.ref) | map({ref: .[0].ref, dependsOn: (map(.dependsOn // []) | add | unique)}))
    | .serialNumber = "urn:uuid:7f60c5df-047a-5ac1-9a38-4f2f7d88c0a1"
    | .citations = [
        {"bom-ref": "cargo-lock-source", pointers: ["/components", "/dependencies"], timestamp: .metadata.timestamp, attributedTo: .metadata.component."bom-ref", note: "Rust dependency inventory derived from Cargo.lock."},
        {"bom-ref": "go-lock-source", pointers: ["/components", "/dependencies"], timestamp: .metadata.timestamp, attributedTo: $go_root_ref, note: "Go helper dependency inventory derived from tools/modern-anisette/go.mod and go.sum."}
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
        if .name == "openssl-macros" then add_vcs("https://github.com/sfackler/rust-openssl") else . end
        | add_supplier
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
  and ([.components[] | select(.name == "stdlib") | ."bom-ref"][0] as $stdlib
    | [.components[] | select(.name == "github.com/majd/ipatool/v2/ipakeep-anisette-helper") | ."bom-ref"][0] as $helper
    | any(.dependencies[]; .ref == $helper and any(.dependsOn[]?; . == $stdlib)))
' "$candidate" > /dev/null
sbomqs score --configpath "$root/sbom/sbomqs-comprehensive.yaml" "$candidate"
sbomqs score --profile ntia "$candidate"
sbom-tools quality "$candidate" --profile comprehensive --recommendations
osv-scanner -L "$candidate"
grype "sbom:$candidate" --fail-on medium
mv "$candidate" "$out"
