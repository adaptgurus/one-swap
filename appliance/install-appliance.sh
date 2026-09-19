#!/usr/bin/env bash
set -euo pipefail

ROOT="${DESTDIR:-}"
SOURCE_ROOT="${1:-$(cd "$(dirname "$0")/.." && pwd)}"

install -d -m 0755 "$ROOT/usr/libexec/layersentry"
install -d -m 0700 "$ROOT/etc/layersentry/oneswapd/tls"
install -d -m 0700 "$ROOT/etc/layersentry/oneswapd/sources"
install -d -m 0700 "$ROOT/etc/layersentry/oneswapd/source-configs"
install -d -m 0700 "$ROOT/etc/layersentry/oneswapd/credentials"
install -d -m 0700 "$ROOT/var/lib/layersentry-oneswap"
install -d -m 0700 "$ROOT/var/cache/layersentry-oneswap"
install -d -m 0755 "$ROOT/usr/lib/systemd/system"

install -m 0755 "$SOURCE_ROOT/appliance/oneswapd.py" "$ROOT/usr/libexec/layersentry/oneswapd"
install -m 0755 "$SOURCE_ROOT/appliance/check-scratch.py" "$ROOT/usr/libexec/layersentry/oneswap-scratch-check"
install -m 0644 "$SOURCE_ROOT/appliance/oneswapd.service" "$ROOT/usr/lib/systemd/system/oneswapd.service"

if [[ ! -e "$ROOT/etc/layersentry/oneswapd/config.json" ]]; then
    install -m 0600 "$SOURCE_ROOT/appliance/config.example.json" "$ROOT/etc/layersentry/oneswapd/config.json"
fi

if [[ -z "$ROOT" ]]; then
    if ! getent group oneswap >/dev/null; then
        groupadd --system oneswap
    fi
    if ! id -u oneswap >/dev/null 2>&1; then
        useradd --system --gid oneswap --home-dir /var/lib/layersentry-oneswap --shell /sbin/nologin oneswap
    fi
    chown -R root:oneswap /etc/layersentry/oneswapd
    chmod 0750 /etc/layersentry/oneswapd /etc/layersentry/oneswapd/{tls,sources,source-configs,credentials}
    chown -R oneswap:oneswap /var/lib/layersentry-oneswap /var/cache/layersentry-oneswap
    if getent group kvm >/dev/null; then
        usermod -a -G kvm oneswap
    fi
    systemctl daemon-reload
fi

echo "LayerSentry OneSwap appliance service installed. Provision TLS/source profiles and a dedicated scratch mount before enabling oneswapd."
