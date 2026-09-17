#!/usr/bin/env bash
# Los vectores de prueba del RFC 9807, corridos contra EXACTAMENTE la versión de opaque-ke que
# compilamos (la de wasm/Cargo.toml).
#
# crates.io publica opaque-ke sin sus pruebas, así que se clona el repositorio en su tag y se
# corre su batería, que incluye src/tests/rfc9807_vectors.rs. Si el tag no coincide con la
# versión fijada, se para: probar otra versión no dice nada de la nuestra.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
version="$(sed -n 's/^opaque-ke = { version = "=\([0-9.]*\)".*/\1/p' "$root/wasm/Cargo.toml")"
if [ -z "$version" ]; then
  echo "vectors: opaque-ke must be pinned with \"=x.y.z\" in wasm/Cargo.toml" >&2
  exit 1
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
git clone --quiet --depth 1 --branch "v$version" https://github.com/facebook/opaque-ke "$work/opaque-ke"
test -f "$work/opaque-ke/src/tests/rfc9807_vectors.rs" || { echo "vectors: v$version has no RFC 9807 vectors" >&2; exit 1; }

cd "$work/opaque-ke"
echo "vectors: running opaque-ke v$version test suite (RFC 9807 vectors included)"
cargo test --quiet --features argon2 2>&1 | tail -20
