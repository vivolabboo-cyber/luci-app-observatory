<p align="center"><img src="docs/images/overview-en.png" alt="Observatory dashboard — entirely synthetic demo data" width="100%"></p>

# Observatory

**A local OpenWrt network observatory: device counters, router health, traffic charts and honest attribution limits.**

[Русский](README.md) · [Security](SECURITY.md) · [License](LICENSE)

## Features

DHCP/ARP/NDP discovery, device counters, CPU/memory/temperature, charts, events and CSV/JSON reports. Optional domain/route estimates require explicitly enabled integrations. Russian and English interface, inherited from LuCI or selected in the dashboard. Includes the matching [ZONA](https://github.com/vivolabboo-cyber/luci-theme-zona) palette.

## Privacy-first defaults

Installation does not start the collector or enable autostart. DNS attribution, connection details and Tachyon integration default to off. Data is stored in private RAM-backed `/tmp` directories (0700; files 0600), lost on reboot. History retention is 7 days; 32 MiB is a soft database maintenance threshold, not a strict disk quota. No cloud uploads, analytics, new HTTP listeners, automatic rpcd restarts or DNS/VPN changes.

The collector needs root to own an `inet observatory` nft counter table. It never adds drop/redirect/mark rules, but it does create counters and local state: it is not a zero-side-effect process. RPC is read-only and protected by existing authenticated LuCI/rpcd ACLs.

## Install

Over SSH as root, download the installer:

```sh
wget -O /tmp/luci-app-observatory-install.sh https://github.com/vivolabboo-cyber/luci-app-observatory/releases/download/v0.2.1/bootstrap.sh
```

Review the script, then run:

```sh
sh /tmp/luci-app-observatory-install.sh --install-deps
```

The installer downloads a pinned release over HTTPS and checks the archive SHA-256. A checksum is not a signature: you still trust GitHub and the installer.

`--install-deps` installs dependencies with apk/opkg from configured firmware repositories. Collection and autostart remain disabled pending LAN/WAN configuration review.

Manual installation:

Requires LuCI, rpcd, nftables, ip-full and Python 3 with sqlite3/urllib. On APK OpenWrt: `apk add python3-light python3-sqlite3 python3-urllib ip-full nftables rpcd`; use matching opkg packages on older firmware. Verify package names for your release. The installer downloads no dependencies.

Review downloaded sources/release checksums, keep normal router backups and SSH access, then run `sh install.sh`. Overwritten program files are backed up under private `/root/observatory-backup-*`. Review `/etc/observatory/config.json` against `config/config.example.json`, especially LAN/WAN names. Then manually reload rpcd (`/etc/init.d/rpcd reload`, may require signing in again), and start the collector (`/etc/init.d/observatory start`). Starting it explicitly enables collection of local device metadata. Autostart is a separate choice: `/etc/init.d/observatory enable`. Open Status → Observatory.

## Optional attribution

`collect_connection_details: true` enables conntrack/connection detail sampling. `tachyon_enabled: true` permits reading the local Clash-compatible API configuration from `/etc/tachyon-core/config.json`. Only loopback/unspecified local bind targets are allowed; private LAN and public controller addresses are rejected. API secrets remain on the router and are never returned to the dashboard. No controller is exposed by this project.

`dns_enabled: true` enables reading an already configured private DNS log. This project does not enable DNS logging for you: it is a separate, privacy-sensitive choice. Persistent storage must be deliberately configured outside `/www`. Never commit real configuration, DNS history, reports or databases.

## Accuracy and development

Device counters include LAN traffic and overhead. DNS queries are not visits. HTTPS content is not inspected. Domain volumes are estimates; short flows, CDN sharing, ECH, offload and proxies can reduce attribution. Names and MACs do not identify people. Exported reports contain local identifiers/domains and are not automatically anonymized. Review before sharing.

Run `python3 tools/check.py`, `python3 -m unittest discover -s tests`, then `python3 tools/package.py`. The Makefile targets OpenWrt SDK packaging. `docs/demo` uses invented data and never contacts your router. The public revision is locally tested and was not deployed over the original household installation during publication. No independent security audit or large-network performance guarantee.

`sh uninstall.sh` stops/disables the collector and removes program files, retaining configuration, history and backups. Restore overwritten files from the selected backup; decide separately whether to restart collection. Apache-2.0.
