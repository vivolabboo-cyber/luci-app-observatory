#!/bin/sh
# Download and review this script before running it as root.
set -eu
VERSION='0.2.1'
PROJECT='luci-app-observatory'
SHA256='ee1668b2e89d927c01e441cfa7f106d59cfb318d9ac04f99782fe9e35d7e7ac9'
activate=0
deps=0
for arg in "$@"; do
    case "$arg" in
        --activate) activate=1 ;;
        --install-deps) deps=1 ;;
        --help|-h) echo "Usage: sh bootstrap.sh [--activate (theme only)] [--install-deps (Observatory only)]"; exit 0 ;;
        *) echo "Unknown option: $arg" >&2; exit 1 ;;
    esac
done
[ "$PROJECT" = 'luci-theme-zona' ] || [ "$activate" -eq 0 ] || { echo '--activate is for the theme only.' >&2; exit 1; }
[ "$PROJECT" = 'luci-app-observatory' ] || [ "$deps" -eq 0 ] || { echo '--install-deps is for Observatory only.' >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || { echo 'Run as root on OpenWrt.' >&2; exit 1; }
[ -f /etc/openwrt_release ] || { echo 'OpenWrt is required.' >&2; exit 1; }
for tool in mktemp tar sha256sum; do
    command -v "$tool" >/dev/null || { echo "Missing required tool: $tool" >&2; exit 1; }
done
umask 077
stage=$(mktemp -d /tmp/observatory-install.XXXXXX)
trap 'rm -rf "$stage"' EXIT
trap 'exit 1' HUP INT TERM
archive="$PROJECT-$VERSION.tar.gz"
url="https://github.com/vivolabboo-cyber/$PROJECT/releases/download/v$VERSION/$archive"
echo "Downloading $PROJECT $VERSION..."
if command -v curl >/dev/null; then
    curl --fail --location --proto '=https' --proto-redir '=https' --tlsv1.2 --retry 2 --max-time 180 --output "$stage/$archive" "$url"
elif command -v wget >/dev/null; then
    wget -O "$stage/$archive" "$url"
else
    echo 'Install curl or wget with working HTTPS certificate verification.' >&2
    exit 1
fi
(cd "$stage"; printf '%s  %s\n' "$SHA256" "$archive" | sha256sum -c -)
# Nothing from the archive is extracted or executed before successful verification.
mkdir "$stage/package"
tar -xzf "$stage/$archive" -C "$stage/package"
if [ "$deps" -eq 1 ]; then
    echo 'Installing dependencies from configured OpenWrt repositories...'
    if command -v apk >/dev/null; then
        apk update
        apk add python3-light python3-sqlite3 python3-urllib ip-full nftables rpcd
    elif command -v opkg >/dev/null; then
        opkg update
        opkg install python3-light python3-sqlite3 python3-urllib ip-full nftables rpcd
    else
        echo 'No supported package manager found.' >&2
        exit 1
    fi
fi
if [ "$activate" -eq 1 ]; then
    sh "$stage/package/install.sh" --activate
else
    sh "$stage/package/install.sh"
fi
