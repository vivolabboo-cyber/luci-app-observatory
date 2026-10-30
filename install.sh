#!/bin/sh
set -eu
[ "$(id -u)" -eq 0 ] || { echo 'Run as root on OpenWrt.' >&2; exit 1; }
[ -f /etc/openwrt_release ] || { echo 'This installer requires OpenWrt.' >&2; exit 1; }
[ -f /usr/share/ucode/luci/runtime.uc ] || [ -d /usr/share/ucode/luci/template ] || { echo 'ucode-based LuCI is required.' >&2; exit 1; }
command -v uci >/dev/null || { echo 'LuCI/UCI is required.' >&2; exit 1; }
python3 -c 'import sqlite3, urllib.request' 2>/dev/null || { echo 'Install python3-light python3-sqlite3 python3-urllib first.' >&2; exit 1; }
command -v nft >/dev/null || { echo 'Install nftables first.' >&2; exit 1; }
command -v ip >/dev/null || { echo 'Install ip-full first.' >&2; exit 1; }
cd "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
umask 077
backup="/root/observatory-backup-$(date +%Y%m%d-%H%M%S)-$$"
mkdir -p "$backup/files"
find root -type f | while IFS= read -r src; do
    rel=${src#root/}
    case "$rel" in /*|*..*) echo 'Invalid package path' >&2; exit 1;; esac
    dest="/$rel"
    if [ -e "$dest" ]; then
        mkdir -p "$backup/files/$(dirname "$rel")"
        cp -p "$dest" "$backup/files/$rel"
    fi
    mkdir -p "$(dirname "$dest")"
    cp "$src" "$dest"
    chmod 644 "$dest"
done
echo "Backup: $backup"

chmod 755 /etc/init.d/observatory /etc/init.d/observatory-logdir /usr/libexec/rpcd/observatory
mkdir -p /etc/observatory
chmod 700 /etc/observatory
if [ ! -e /etc/observatory/config.json ]; then
    cp config/config.example.json /etc/observatory/config.json
    chmod 600 /etc/observatory/config.json
fi
echo 'Installed but NOT started or enabled. Review config and docs before starting.'
echo 'rpcd was not restarted. Reload it manually at a convenient time to register the plugin.'
