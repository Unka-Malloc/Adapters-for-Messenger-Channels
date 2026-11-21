#!/usr/bin/env bash
# Local packaging check: every crate nightly tag packaging would publish
# resolves a contract crate carrying the API it uses.
#
# `a4mc` packages with full verification — its dependencies are already
# published. Each a4mc-<channel> dialect is then packaged against a
# vendored source that contains the packaged a4mc plus every registry
# dependency, mirroring the index state after the `a4mc-v*` tag
# publishes first. Cargo's own package verify step rebuilds each
# packaged dialect against that contract crate, so a manifest that
# required a contract release without the outbound API fails here —
# not at the nightly tag. Publish order stays a4mc before dialects.
set -euo pipefail
cd "$(dirname "$0")/.."

rm -f target/package/a4mc-*.crate
cargo package --locked --allow-dirty -p a4mc

scratch="$(mktemp -d "${TMPDIR:-/tmp}/a4mc-package-check.XXXXXX")"
trap 'rm -rf "$scratch"' EXIT

cargo vendor "$scratch/vendor" >/dev/null
packed="$(echo target/package/a4mc-[0-9]*.crate)"
tar -xzf "$packed" -C "$scratch/vendor"
mv "$scratch"/vendor/a4mc-[0-9]* "$scratch/vendor/a4mc"
python3 - "$scratch/vendor/a4mc" "$packed" <<'PY'
import hashlib, json, os, sys
root, packed = sys.argv[1], sys.argv[2]
files = {}
for dirpath, _, names in os.walk(root):
    for name in names:
        path = os.path.join(dirpath, name)
        files[os.path.relpath(path, root)] = hashlib.sha256(
            open(path, "rb").read()
        ).hexdigest()
checksum = {
    "files": files,
    "package": hashlib.sha256(open(packed, "rb").read()).hexdigest(),
}
with open(os.path.join(root, ".cargo-checksum.json"), "w") as out:
    json.dump(checksum, out)
PY

for crate in a4mc-telegram a4mc-slack a4mc-discord a4mc-webhook; do
    cargo --config 'source.crates-io.replace-with="vendored-sources"' \
        --config "source.vendored-sources.directory=\"$scratch/vendor\"" \
        package --locked --allow-dirty -p "$crate"
done
