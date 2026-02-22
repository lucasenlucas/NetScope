#!/usr/bin/env sh
set -eu

# Usage:
#   curl -fsSL https://raw.githubusercontent.com/lucasenlucas/NetScope/main/scripts/install.sh | sh
#   Or: REPO="owner/repo" sh install.sh
#
# Installs latest GitHub Release asset into /usr/local/bin (or ~/.local/bin if not writable)
# Automatically detects architecture (amd64/arm64) and OS (Linux/macOS/Windows)

REPO="${REPO:-lucasenlucas/NetScope}"
BIN_NAME="netscope"

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH_RAW="$(uname -m)"

case "$OS" in
  linux) OS="linux" ;;
  darwin) OS="darwin" ;;
  msys*|mingw*|cygwin*) OS="windows" ;;
esac

case "$ARCH_RAW" in
  x86_64|amd64) ARCH="amd64" ;;
  arm64|aarch64) ARCH="arm64" ;;
  *) 
    echo "❌ Unknown architecture: $ARCH_RAW"
    echo "Supported: x86_64/amd64, arm64/aarch64"
    exit 1
    ;;
esac

echo "🔍 Detected: OS=$OS, Architecture=$ARCH ($ARCH_RAW)"

# Password Protection
MANDATORY_PW="NeT\$cope9!Xr7@Lq2"
clear
echo "===================================================="
echo "          🔒 NETSCOPE INSTALLATION GUARD            "
echo "===================================================="
echo ""
printf "  ❯ Voer het installatie-wachtwoord in: "
stty -echo < /dev/tty
read -r user_pw < /dev/tty
stty echo < /dev/tty
echo ""
echo "===================================================="

if [ "$user_pw" != "$MANDATORY_PW" ]; then
  echo ""
  echo "  ❌ Fout: Ongeldig wachtwoord."
  echo "  Installatie afgebroken voor veiligheid."
  echo ""
  exit 1
fi

echo ""
echo "  ✅ Wachtwoord correct! Toegang verleend."
echo "  Bezig met ophalen van de nieuwste release..."
echo ""

api="https://api.github.com/repos/${REPO}/releases/latest"

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

echo "📦 Downloading latest release from ${REPO} for ${OS}/${ARCH}..."

# Expect artifact naming like: netscope_<os>_<arch>.tar.gz (or .zip for windows)
asset=""
json="$(curl -fsSL "$api")"
asset="$(printf "%s" "$json" | grep -Eo '"browser_download_url":[^"]*"[^"]+"' | cut -d'"' -f4 | grep -E "${OS}_${ARCH}" | head -n 1 || true)"

if [ -z "$asset" ]; then
  echo "❌ No release asset found for ${OS}_${ARCH}."
  echo "Check https://github.com/${REPO}/releases"
  exit 1
fi

cd "$tmpdir"
echo "⬇️  Downloading: $(basename "$asset")"
curl -fsSL -o asset "$asset"

# Try /usr/local/bin first (requires sudo on some systems)
dest="/usr/local/bin"
needs_sudo=false
if [ ! -w "$dest" ]; then
  # Check if sudo is available
  if command -v sudo >/dev/null 2>&1; then
    needs_sudo=true
  else
    # Fallback to ~/.local/bin if sudo not available
    dest="${HOME}/.local/bin"
    mkdir -p "$dest"
  fi
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

# Function to install binary
install_bin() {
  bin="$1"
  
  # Handle windows extension check if needed
  if [ ! -f "./${bin}" ] && [ -f "./${bin}.exe" ]; then
    bin="${bin}.exe"
  fi

  if [ ! -f "./${bin}" ]; then
    echo "⚠️  Binary ${bin} not found in archive."
    return
  fi

  chmod +x "./${bin}"
  
  if [ "$needs_sudo" = true ]; then
    echo "🔐 Installing ${bin} to ${dest}..."
    sudo mv "./${bin}" "${dest}/${bin%.exe}"
    sudo chmod +x "${dest}/${bin%.exe}"
  else
    echo "📁 Installing ${bin} to ${dest}..."
    mv "./${bin}" "${dest}/${bin%.exe}"
    chmod +x "${dest}/${bin%.exe}"
  fi
  echo "✅ ${bin} successfully installed"
}

# Install NetScope
install_bin "$BIN_NAME"

echo ""

# Check if dest is in PATH
if [ "$dest" = "${HOME}/.local/bin" ]; then
  if ! echo "$PATH" | grep -q "${HOME}/.local/bin"; then
    echo "⚠️  ${dest} is not in your PATH!"
    echo ""
    # Detect shell
    if [ -n "${ZSH_VERSION:-}" ]; then
      SHELL_RC="$HOME/.zshrc"
    elif [ -n "${BASH_VERSION:-}" ]; then
      SHELL_RC="$HOME/.bashrc"
    else
      SHELL_RC="$HOME/.profile"
    fi
    
    echo "Add this to your ${SHELL_RC}:"
    echo "  export PATH=\"\$HOME/.local/bin:\$PATH\""
    echo ""
    echo "Or run directly:"
    echo "  echo 'export PATH=\"\$HOME/.local/bin:\$PATH\"' >> ${SHELL_RC}"
    echo "  source ${SHELL_RC}"
    echo ""
    echo "Or test direct: ${dest}/${BIN_NAME} --help"
  else
    if command -v "${BIN_NAME}" >/dev/null 2>&1; then
      echo "🎉 Done! Run: ${BIN_NAME} --help"
    fi
  fi
else
  # Test if it works
  if command -v "${BIN_NAME}" >/dev/null 2>&1; then
    echo "🎉 Done! Run: ${BIN_NAME} --help"
  else
    echo "⚠️  ${BIN_NAME} is possibly not in your PATH."
    echo "   Run: export PATH=\"${dest}:\$PATH\""
    echo "   Or open a new terminal."
  fi
fi
