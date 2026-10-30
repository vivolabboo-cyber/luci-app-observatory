#!/bin/sh
set -eu
[ "$(id -u)" -eq 0 ] || exit 1
cd "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
/etc/init.d/observatory stop || true
/etc/init.d/observatory disable || true
/etc/init.d/observatory-logdir disable || true
find root -type f | while IFS= read -r src; do
    case "$src" in root/usr/lib/observatory/*|root/usr/libexec/rpcd/observatory|root/etc/init.d/observatory|root/etc/init.d/observatory-logdir|root/www/luci-static/resources/observatory/*|root/www/luci-static/resources/view/status/observatory.js|root/usr/share/rpcd/acl.d/luci-app-observatory.json|root/usr/share/luci/menu.d/luci-app-observatory.json|root/usr/share/observatory/i18n/*|root/lib/upgrade/keep.d/observatory) rm -f "/${src#root/}";; *) echo 'Skipped unexpected path' >&2;; esac
done
echo 'Program removed. Configuration, local history, and backups preserved.'
