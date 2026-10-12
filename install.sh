#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# AegisGate Scanner — Install Script
# ============================================================================
# Installs the latest release of aegisgate-scanner to /usr/local/bin.
#
# Usage:
#   curl -sSL https://raw.githubusercontent.com/aegisgatesecurity/aegisgate-scanner/main/install.sh | bash
#
# Or to install a specific version:
#   curl -sSL https://raw.githubusercontent.com/aegisgatesecurity/aegisgate-scanner/main/install.sh | bash -s -- v0.1.0
#
# Environment variables:
#   INSTALL_DIR  — installation directory (default: /usr/local/bin)
#   VERSION      — specific version to install (default: latest)
# ============================================================================

set -e

REPO="aegisgatesecurity/aegisgate-scanner"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
BINARY_NAME="aegisgate-scanner"

# Color output (if terminal supports it).
if [ -t 1 ]; then
	RED='\033[0;31m'
	GREEN='\033[0;32m'
	YELLOW='\033[0;33m'
	NC='\033[0m'
else
	RED=''
	GREEN=''
	YELLOW=''
	NC=''
fi

info()  { printf "${GREEN}✓${NC} %s\n" "$1"; }
warn()  { printf "${YELLOW}⚠${NC} %s\n" "$1"; }
error() { printf "${RED}✗${NC} %s\n" "$1"; exit 1; }

# --- Determine version -------------------------------------------------------
if [ -n "$1" ]; then
	VERSION="$1"
elif [ -z "$VERSION" ]; then
	# Fetch latest release tag from GitHub API.
	VERSION=$(curl -sSL "https://api.github.com/repos/${REPO}/releases/latest" \
		| grep '"tag_name"' \
		| sed -E 's/.*"([^"]+)".*/\1/')
	if [ -z "$VERSION" ]; then
		error "Could not determine latest version. Specify explicitly: install.sh v0.1.0"
	fi
fi

# Strip leading 'v' for URL construction.
VERSION_NUM="${VERSION#v}"

# --- Detect OS and architecture ----------------------------------------------
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "$OS" in
	linux)  OS="linux"  ;;
	darwin) OS="darwin" ;;
	*)      error "Unsupported OS: $OS" ;;
esac

case "$ARCH" in
	x86_64|amd64)  ARCH="amd64"  ;;
	aarch64|arm64) ARCH="arm64"  ;;
	*)             error "Unsupported architecture: $ARCH" ;;
esac

# --- Determine download variant ----------------------------------------------
# Lite (heuristic-only) builds are available for all platforms.
# ML-enabled builds require CGO and are platform-specific.
VARIANT="${VARIANT:-lite}"
SUFFIX="${OS}-${ARCH}"

if [ "$VARIANT" = "ml" ]; then
	SUFFIX="${OS}-${ARCH}-ml"
fi

DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${VERSION}/${BINARY_NAME}-${SUFFIX}"
CHECKSUM_URL="https://github.com/${REPO}/releases/download/${VERSION}/${BINARY_NAME}-${SUFFIX}.sha256"

# --- Create temp directory ---------------------------------------------------
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

# --- Download binary ---------------------------------------------------------
echo "Installing aegisgate-scanner ${VERSION} (${VARIANT}/${OS}/${ARCH})..."

BINARY_PATH="${TMP_DIR}/${BINARY_NAME}"

if ! curl -sSL --fail "$DOWNLOAD_URL" -o "$BINARY_PATH"; then
	# Fallback: try without variant suffix (lite is the default).
	DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${VERSION}/${BINARY_NAME}-${OS}-${ARCH}"
	CHECKSUM_URL="https://github.com/${REPO}/releases/download/${VERSION}/${BINARY_NAME}-${OS}-${ARCH}.sha256"
	if ! curl -sSL --fail "$DOWNLOAD_URL" -o "$BINARY_PATH"; then
		error "Failed to download binary from:\n  $DOWNLOAD_URL\n\nCheck that version ${VERSION} exists at:\n  https://github.com/${REPO}/releases/tag/${VERSION}"
	fi
fi
info "Downloaded binary"

# --- Verify checksum (if available) -----------------------------------------
CHECKSUM_PATH="${TMP_DIR}/checksum.txt"
if curl -sSL --fail "$CHECKSUM_URL" -o "$CHECKSUM_PATH" 2>/dev/null; then
	EXPECTED=$(awk '{print $1}' "$CHECKSUM_PATH")
	ACTUAL=$(sha256sum "$BINARY_PATH" | awk '{print $1}')
	if [ "$EXPECTED" != "$ACTUAL" ]; then
		error "Checksum verification failed!\n  Expected: $EXPECTED\n  Actual:   $ACTUAL"
	fi
	info "Checksum verified"
else
	warn "No checksum file found (skipping verification)"
fi

# --- Install -----------------------------------------------------------------
chmod +x "$BINARY_PATH"

# Try to install to INSTALL_DIR, fall back to sudo if needed.
if [ -w "$INSTALL_DIR" ]; then
	mv "$BINARY_PATH" "${INSTALL_DIR}/${BINARY_NAME}"
else
	warn "No write access to ${INSTALL_DIR}, using sudo"
	sudo mv "$BINARY_PATH" "${INSTALL_DIR}/${BINARY_NAME}"
fi
info "Installed to ${INSTALL_DIR}/${BINARY_NAME}"

# --- Verify ------------------------------------------------------------------
if command -v "$BINARY_NAME" >/dev/null 2>&1; then
	INSTALLED=$("$BINARY_NAME" --version 2>&1 || echo "unknown")
	info "aegisgate-scanner installed: ${INSTALLED}"
else
	warn "Add ${INSTALL_DIR} to your PATH to use aegisgate-scanner"
fi

echo ""
echo "Quick start:"
echo "  aegisgate-scanner scan ."
echo "  aegisgate-scanner scan --format jsonl . | jq ."
echo "  aegisgate-scanner scan --format sarif . > results.sarif"