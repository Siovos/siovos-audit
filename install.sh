#!/bin/sh
set -e

# Siovos Audit installer
# Usage: curl -fsSL https://raw.githubusercontent.com/Siovos/siovos-audit/main/install.sh | sh

REPO="Siovos/siovos-audit"
INSTALL_DIR="/usr/local/bin"
BINARY="siovos-audit"

main() {
    detect_platform
    get_latest_version
    download_and_install
    verify_installation
}

detect_platform() {
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    ARCH=$(uname -m)

    case "$ARCH" in
        x86_64|amd64) ARCH="amd64" ;;
        aarch64|arm64) ARCH="arm64" ;;
        *) echo "Unsupported architecture: $ARCH" && exit 1 ;;
    esac

    case "$OS" in
        linux) ;;
        darwin) ARCH="all" ;;
        *) echo "Unsupported OS: $OS" && exit 1 ;;
    esac

    echo "Platform: ${OS}/${ARCH}"
}

get_latest_version() {
    VERSION=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | sed -E 's/.*"v([^"]+)".*/\1/')
    if [ -z "$VERSION" ]; then
        echo "Failed to get latest version"
        exit 1
    fi
    echo "Latest version: v${VERSION}"
}

download_and_install() {
    FILENAME="${BINARY}_${VERSION}_${OS}_${ARCH}.tar.gz"
    URL="https://github.com/${REPO}/releases/download/v${VERSION}/${FILENAME}"

    echo "Downloading ${URL}..."

    TMP=$(mktemp -d)
    trap "rm -rf $TMP" EXIT

    curl -fsSL "$URL" -o "${TMP}/${FILENAME}"
    tar xzf "${TMP}/${FILENAME}" -C "$TMP"

    if [ -w "$INSTALL_DIR" ]; then
        mv "${TMP}/${BINARY}" "${INSTALL_DIR}/${BINARY}"
    else
        echo "Installing to ${INSTALL_DIR} (requires sudo)..."
        sudo mv "${TMP}/${BINARY}" "${INSTALL_DIR}/${BINARY}"
    fi

    chmod +x "${INSTALL_DIR}/${BINARY}"
}

verify_installation() {
    if command -v "$BINARY" >/dev/null 2>&1; then
        echo ""
        echo "Installed: $(${BINARY} version)"
        echo ""
        echo "Quick start:"
        echo "  siovos-audit run --host <ip> --user <user>"
        echo "  siovos-audit run --local"
        echo "  siovos-audit run              # interactive mode"
    else
        echo ""
        echo "Installed to ${INSTALL_DIR}/${BINARY}"
        echo "If the command is not found, add ${INSTALL_DIR} to your PATH"
    fi
}

main
