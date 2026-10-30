#!/bin/sh
set -eu
[ "$(id -u)" -eq 0 ] || { echo 'Run as root on OpenWrt.' >&2; exit 1; }
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
