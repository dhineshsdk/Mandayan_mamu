#!/usr/bin/env bash
# Build the offline install bundle. Run this on a machine WITH internet access, on the same operating system, CPU
# architecture and Python minor version as the server it is for (some dependencies are compiled wheels).
#
#   packaging/build-bundle.sh [output-dir]      -> <output-dir>/sutra-<version>-linux-<arch>-py<NN>.tar.gz (+ .sha256)
#
# Set WITH_CLOUD_AI=1 to also include the Anthropic SDK (needed only if the customer allows the Claude API).
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out="$(mkdir -p "${1:-$root/dist}" && cd "${1:-$root/dist}" && pwd)"
py="${PYTHON:-python3}"

version="$("$py" -c 'import tomllib;print(tomllib.load(open("pyproject.toml","rb"))["project"]["version"])')"
tag="$("$py" -c 'import sys;print(f"py{sys.version_info.major}{sys.version_info.minor}")')"
name="sutra-${version}-linux-$(uname -m)-${tag}"
stage="${out:?}/${name:?}"

cd "$root"
rm -rf "${stage:?}" "${out:?}/${name:?}.tar.gz" "${out:?}/${name:?}.tar.gz.sha256"
mkdir -p "$stage/wheelhouse"

target="."
[ "${WITH_CLOUD_AI:-0}" = "1" ] && target=".[ai]"
# One resolution for everything: Sutra, its local packages and every dependency, as wheels.
"$py" -m pip wheel --quiet --wheel-dir "$stage/wheelhouse" ./patchdraft ./connectors ./compliance ./explain "$target"

install -m 0755 packaging/install.sh packaging/upgrade.sh "$stage/"
cp -r packaging/systemd "$stage/systemd"
install -m 0644 packaging/sutra.env.example packaging/nginx.conf.example "$stage/"
mkdir -p "$stage/docs"
cp docs/*.md "$stage/docs/"
cp README.md "$stage/README.md"
echo "$tag" > "$stage/PYTHON_TAG"
echo "$version" > "$stage/VERSION"

# shellcheck disable=SC2094  # SHA256SUMS is excluded from the list it is written from
( cd "$stage" && find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS )
tar -C "$out" -czf "$out/$name.tar.gz" "$name"
( cd "$out" && sha256sum "$name.tar.gz" > "$name.tar.gz.sha256" )
rm -rf "${stage:?}"
echo "Built $out/$name.tar.gz"
echo "Copy it and its .sha256 file to the server (USB, secure file transfer) and follow docs/installation.md."
