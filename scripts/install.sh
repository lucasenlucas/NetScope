#!/usr/bin/env sh
set -eu

# Usage:
#   REPO="owner/repo" sh install.sh
#   (default) REPO="lucasdns/lucasdns"
#
# Installs latest GitHub Release asset into /usr/local/bin (or ~/.local/bin if not writable)

REPO="${REPO:-lucasdns/lucasdns}"
BIN_NAME="${BIN_NAME:-lucasdns}"

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

case "$OS" in
  linux) OS="linux" ;;
  darwin) OS="darwin" ;;
  msys*|mingw*|cygwin*) OS="windows" ;;
esac

case "$ARCH" in
  x86_64|amd64) ARCH="amd64" ;;
  arm64|aarch64) ARCH="arm64" ;;
esac

api="https://api.github.com/repos/${REPO}/releases/latest"

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

echo "Downloading latest release from ${REPO} for ${OS}/${ARCH}..."

# Expect artifact naming like: lucasdns_<os>_<arch>.tar.gz (or .zip for windows)
asset=""
json="$(curl -fsSL "$api")"
asset="$(printf "%s" "$json" | grep -Eo '"browser_download_url":[^"]*"[^"]+"' | cut -d'"' -f4 | grep -E "${OS}_${ARCH}" | head -n 1 || true)"

if [ -z "$asset" ]; then
  echo "Could not find a release asset matching ${OS}_${ARCH}."
  echo "Check the releases page or set REPO/BIN_NAME."
  exit 1
fi

cd "$tmpdir"
curl -fsSL -o asset "$asset"

dest="/usr/local/bin"
if [ ! -w "$dest" ]; then
  dest="${HOME}/.local/bin"
  mkdir -p "$dest"
fi

case "$asset" in
  *.tar.gz)
    tar -xzf asset
    ;;
  *.zip)
    unzip -q asset
    ;;
  *)
    echo "Unknown archive format: $asset"
    exit 1
    ;;
esac

if [ ! -f "./${BIN_NAME}" ] && [ -f "./${BIN_NAME}.exe" ]; then
  BIN_NAME="${BIN_NAME}.exe"
fi

if [ ! -f "./${BIN_NAME}" ]; then
  echo "Binary ${BIN_NAME} not found in archive."
  exit 1
fi

chmod +x "./${BIN_NAME}"
mv "./${BIN_NAME}" "${dest}/lucasdns"

echo "Installed to ${dest}/lucasdns"
echo "Run: lucasdns --help"

