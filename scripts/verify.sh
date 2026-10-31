#!/usr/bin/env bash
# Single-shot verification gate for the A4MC workspace: format, lint and
# deterministic tests across the a4mc contract crate and every a4mc-<channel>
# dialect crate.
set -euo pipefail
cd "$(dirname "$0")/.."

cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
