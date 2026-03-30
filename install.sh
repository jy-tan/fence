#!/bin/sh
set -e

# Fence Installer (Linux/macOS only)
# For Windows, we recommend using WSL.
# Usage (latest):
#   curl -fsSL https://raw.githubusercontent.com/Use-Tusk/fence/main/install.sh | sh
# Usage (specific version):
#   curl -fsSL https://raw.githubusercontent.com/Use-Tusk/fence/main/install.sh | sh -s -- v0.1.0
# Or via env var:
#   curl -fsSL https://raw.githubusercontent.com/Use-Tusk/fence/main/install.sh | FENCE_VERSION=0.1.0 sh

REPO="Use-Tusk/fence"
BINARY_NAME="fence"

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "$OS" in
  linux*)  OS="linux" ;;
  darwin*) OS="darwin" ;;
  mingw*|msys*|cygwin*)
    echo "Error: This script is for Linux/macOS only."
    echo "For Windows, we recommend using WSL."
    exit 1
    ;;
  *)
    echo "Unsupported operating system: $OS"
    exit 1
    ;;
esac

case "$ARCH" in
  x86_64|amd64) ARCH="x86_64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *)
    echo "Unsupported architecture: $ARCH"
    exit 1
    ;;
esac

# Determine version to install: use first arg or FENCE_VERSION env var; otherwise fallback to latest
REQUESTED_VERSION="${1:-${FENCE_VERSION:-}}"
if [ -n "$REQUESTED_VERSION" ]; then
  case "$REQUESTED_VERSION" in
    v*) VERSION_TAG="$REQUESTED_VERSION" ;;
    *)  VERSION_TAG="v$REQUESTED_VERSION" ;;
  esac
else
  # Try manifest first (fast, no rate limits)
  VERSION_TAG=$(curl -sL "https://use-tusk.github.io/fence/latest.txt" 2>/dev/null || echo "")
  
  # Fallback to GitHub API if manifest fails
  if [ -z "$VERSION_TAG" ]; then
    VERSION_TAG=$(curl -s "https://api.github.com/repos/$REPO/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
  fi
fi

if [ -z "$VERSION_TAG" ]; then
  echo "Error: Unable to determine version to install"
  exit 1
fi

VERSION_NUMBER="${VERSION_TAG#v}"

case "$OS" in
  linux)  OS_TITLE="Linux" ;;
  darwin) OS_TITLE="Darwin" ;;
  *)      OS_TITLE="$OS" ;;
esac

DOWNLOAD_URL="https://github.com/$REPO/releases/download/${VERSION_TAG}/${BINARY_NAME}_${VERSION_NUMBER}_${OS_TITLE}_${ARCH}.tar.gz"

TMP_DIR=$(mktemp -d)
cd "$TMP_DIR"

echo "Downloading from $DOWNLOAD_URL..."
if ! curl -fsSL -o fence.tar.gz "$DOWNLOAD_URL"; then
  echo "Error: Failed to download release"
  exit 1
fi

tar -xzf fence.tar.gz

# Install to /usr/local/bin or ~/.local/bin
INSTALL_DIR="/usr/local/bin"
if [ ! -w "$INSTALL_DIR" ]; then
  INSTALL_DIR="$HOME/.local/bin"
  mkdir -p "$INSTALL_DIR"
fi

echo "Installing to $INSTALL_DIR..."
mv "$BINARY_NAME" "$INSTALL_DIR/"
chmod +x "$INSTALL_DIR/$BINARY_NAME"

# Cleanup
cd - > /dev/null
rm -rf "$TMP_DIR"

echo "Fence $VERSION_TAG installed successfully!"
echo ""
echo "Run 'fence --help' to get started."

# Check if install dir is in PATH
case ":$PATH:" in
  *":$INSTALL_DIR:"*) ;;
  *)
    echo ""
    echo "⚠️  Add $INSTALL_DIR to your PATH:"
    echo "   export PATH=\"\$PATH:$INSTALL_DIR\""
    ;;
esac

