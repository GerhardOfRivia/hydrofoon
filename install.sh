#!/usr/bin/env sh
# hydrofoon installer - https://github.com/GerhardOfRivia/hydrofoon
# Usage: curl -fsSL https://raw.githubusercontent.com/GerhardOfRivia/hydrofoon/refs/heads/main/install.sh | sh

set -eu

PACKAGE="hydrofoon"
REPO="GerhardOfRivia/${PACKAGE}"
INSTALL_DIR="${HYDROFOON_INSTALL_DIR:-$HOME/.local/bin}"
TEMP_DIR=""
STAGED_BIN=""

if [ -t 1 ] &&
   [ -z "${NO_COLOR:-}" ] &&
   [ "${TERM:-dumb}" != dumb ] &&
   command -v tput >/dev/null 2>&1 &&
   colors=$(tput colors 2>/dev/null) &&
   [ "$colors" -ge 8 ] 2>/dev/null &&
   GREEN=$(tput setaf 2 2>/dev/null) &&
   YELLOW=$(tput setaf 3 2>/dev/null) &&
   RED=$(tput setaf 1 2>/dev/null) &&
   NC=$(tput sgr0 2>/dev/null)
then
    : # Color setup succeeded.
else
    GREEN='' YELLOW='' RED='' NC=''
fi

info() {
    printf '%s[INFO]%s %s\n' "$GREEN" "$NC" "$*"
}

warn() {
    printf '%s[WARN]%s %s\n' "$YELLOW" "$NC" "$*"
}

error() {
    printf '%s[ERROR]%s %s\n' "$RED" "$NC" "$*"
    exit 1
}

cleanup() {
    if [ -n "$STAGED_BIN" ]; then
        rm -f -- "$STAGED_BIN"
    fi
    if [ -n "$TEMP_DIR" ]; then
        rm -rf -- "$TEMP_DIR"
    fi
}

# Detect OS
detect_os() {
    case "$(uname -s)" in
        Linux*)  OS="linux";;
        *)       error "Unsupported operating system: $(uname -s)";;
    esac
}

# Detect architecture
detect_arch() {
    case "$(uname -m)" in
        x86_64|amd64)  ARCH="amd64";;
        arm64|aarch64) ARCH="arm64";;
        *)             error "Unsupported architecture: $(uname -m)";;
    esac
}

# Get latest release version
# Follow the web redirect first, then fall back to the GitHub REST API.
get_latest_version() {
    VERSION=""
    if LATEST_URL=$(curl -fsSLI -o /dev/null -w '%{url_effective}' "https://github.com/${REPO}/releases/latest"); then
        case "$LATEST_URL" in
            "https://github.com/${REPO}/releases/tag/"*)
                VERSION=${LATEST_URL#"https://github.com/${REPO}/releases/tag/"}
                ;;
        esac
    fi
    # Encoded or unexpected redirect tags can still be resolved through the API.
    case "$VERSION" in
        *[!A-Za-z0-9.+-]*) VERSION="";;
    esac

    # Fallback to the REST API if the redirect didn't yield a tag.
    if [ -z "$VERSION" ]; then
        warn "Redirect lookup failed, falling back to GitHub API..."
        if ! RELEASE_JSON=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest"); then
            error "Failed to get latest release; set HYDROFOON_VERSION=vX.Y.Z to pin a version"
        fi
        VERSION=$(printf '%s\n' "$RELEASE_JSON" | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
    fi

    if [ -z "$VERSION" ]; then
        error "Failed to get latest version (GitHub API may be rate-limited; set HYDROFOON_VERSION=vX.Y.Z to pin)"
    fi
}

# Download and install
install() {
    info "Detected: $OS $ARCH"
    info "Target: $TARGET"
    info "Version: $VERSION"

    CHECKSUMS_URL="https://github.com/${REPO}/releases/download/${VERSION}/checksums.txt"
    TEMP_DIR=$(mktemp -d)
    CHECKSUMS="${TEMP_DIR}/checksums.txt"

    if [ "${HYDROFOON_SKIP_CHECKSUM:-0}" = "1" ]; then
        warn "HYDROFOON_SKIP_CHECKSUM=1 set — SKIPPING checksum verification (NOT RECOMMENDED)"
    else
        info "Downloading checksums..."
        if ! curl -fsSL "$CHECKSUMS_URL" -o "$CHECKSUMS"; then
            error "Failed to download checksums.txt — refusing to install unverified binary (set HYDROFOON_SKIP_CHECKSUM=1 to bypass at your own risk)"
        fi
    fi

    ASSET_NAME="${PACKAGE}-${TARGET}.tar"
    DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${VERSION}/${ASSET_NAME}"
    ARCHIVE="${TEMP_DIR}/${ASSET_NAME}"

    info "Downloading from: $DOWNLOAD_URL"
    if ! curl -fsSL "$DOWNLOAD_URL" -o "$ARCHIVE"; then
        error "Failed to download ${PACKAGE}"
    fi

    if [ "${HYDROFOON_SKIP_CHECKSUM:-0}" != "1" ]; then
        info "Verifying SHA-256 checksum for ${PACKAGE}..."
        EXPECTED=$(awk -v asset="$ASSET_NAME" '$2 == asset || $2 == "release/" asset { print $1; exit }' "$CHECKSUMS")
        if [ -z "$EXPECTED" ]; then
            error "checksum for ${ASSET_NAME} not found in checksums.txt — refusing to install"
        fi
        # Prefer sha256sum, with shasum as a portable fallback.
        if command -v sha256sum >/dev/null 2>&1; then
            ACTUAL=$(sha256sum < "$ARCHIVE") || error "Failed to calculate SHA-256 checksum"
        elif command -v shasum >/dev/null 2>&1; then
            ACTUAL=$(shasum -a 256 < "$ARCHIVE") || error "Failed to calculate SHA-256 checksum"
        else
            error "Neither sha256sum nor shasum available — cannot verify checksum"
        fi
        ACTUAL=${ACTUAL%% *}
        if [ "$EXPECTED" != "$ACTUAL" ]; then
            error "checksum mismatch for ${ASSET_NAME}! expected=${EXPECTED} actual=${ACTUAL} — refusing to install"
        fi
        info "Checksum verified for ${PACKAGE}."
    fi

    if ! tar -xf "$ARCHIVE" -C "$TEMP_DIR" "$PACKAGE"; then
        error "Failed to extract ${PACKAGE} from the release archive"
    fi
    if [ ! -f "${TEMP_DIR}/${PACKAGE}" ] || [ -L "${TEMP_DIR}/${PACKAGE}" ]; then
        error "Release archive must contain a regular ${PACKAGE} binary"
    fi

    mkdir -p "$INSTALL_DIR"
    INSTALL_DIR=$(cd "$INSTALL_DIR" && pwd -P)
    INSTALLED_BIN="${INSTALL_DIR}/${PACKAGE}"
    if [ -d "$INSTALLED_BIN" ]; then
        error "Install destination is a directory: $INSTALLED_BIN"
    fi

    # Stage beside the destination so the final replacement is an atomic rename.
    STAGED_BIN=$(mktemp "${INSTALL_DIR}/.${PACKAGE}.XXXXXX")
    cp "${TEMP_DIR}/${PACKAGE}" "$STAGED_BIN"
    chmod 755 "$STAGED_BIN"
    if ! BINARY_VERSION=$("$STAGED_BIN" version); then
        error "Downloaded ${PACKAGE} failed its version check"
    fi
    if [ "$BINARY_VERSION" != "${PACKAGE} ${VERSION}" ]; then
        error "Unexpected binary version: ${BINARY_VERSION}; expected ${PACKAGE} ${VERSION}"
    fi
    mv -f -- "$STAGED_BIN" "$INSTALLED_BIN"
    STAGED_BIN=""
    info "Verification: $BINARY_VERSION"
    info "Successfully installed ${PACKAGE} to ${INSTALLED_BIN}"
}

check_path() {
    if [ "$(command -v "$PACKAGE" || true)" != "$INSTALLED_BIN" ]; then
        warn "To use this installation, add to your shell profile:"
        PATH_DIR=$(printf '%s' "$INSTALL_DIR" | sed 's/[\\"$`]/\\&/g')
        warn "  export PATH=\"${PATH_DIR}:\$PATH\""
    fi
}

main() {
    info "Installing hydrofoon..."

    command -v curl >/dev/null 2>&1 || error "curl is required to download releases"

    detect_os
    detect_arch
    TARGET="${OS}-${ARCH}"
    if [ -n "${HYDROFOON_VERSION:-}" ]; then
        VERSION="$HYDROFOON_VERSION"
        info "Using pinned version from HYDROFOON_VERSION: $VERSION"
    else
        get_latest_version
    fi
    case "$VERSION" in
        ''|*[!A-Za-z0-9.+-]*) error "Unsupported release version: $VERSION";;
    esac
    install
    check_path

    echo ""
    
    info "Installation complete! To run without root install into a root-owned location, then grant only the raw-socket capability."
    info "  sudo install -o root -g root -m 0755 ${INSTALL_DIR}/hydrofoon /usr/local/bin/${PACKAGE}"
    info "  sudo setcap cap_net_raw=ep /usr/local/bin/${PACKAGE}"

    info "Run '${PACKAGE} --help' to get started."
}

main
