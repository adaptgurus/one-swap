#!/usr/bin/env bash
set -euo pipefail

# This is the qualification-time resolver. The production QCOW2 builder never
# talks to package repositories; it consumes only the immutable output bundle.
# Pin the resolver container by digest, not by a floating tag.
RESOLVER_IMAGE="${RESOLVER_IMAGE:?RESOLVER_IMAGE must be an immutable debian:12@sha256:... reference}"
OPENNEBULA_RELEASE="${OPENNEBULA_RELEASE:-7.4.1}"
OUTPUT="${OUTPUT:-$PWD/layersentry-oneswap-packages-${OPENNEBULA_RELEASE}.tar.gz}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

case "$RESOLVER_IMAGE" in
  *@sha256:*) ;;
  *) echo "RESOLVER_IMAGE must be pinned by sha256 digest" >&2; exit 2 ;;
esac

command -v docker >/dev/null || { echo "docker is required to resolve the offline package closure" >&2; exit 2; }
command -v sha256sum >/dev/null || { echo "sha256sum is required" >&2; exit 2; }

bundle_dir="$WORK/bundle"
mkdir -p "$bundle_dir/debs"

# Download the exact dependency closure into a host-mounted directory, then
# record every package/version/architecture and every .deb digest. Re-running
# this resolver can produce a new bundle only by producing a new explicit hash.
docker run --rm \
  -e OPENNEBULA_RELEASE="$OPENNEBULA_RELEASE" \
  -v "$bundle_dir:/bundle" \
  "$RESOLVER_IMAGE" /bin/bash -euo pipefail -c '
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y --no-install-recommends ca-certificates gnupg wget apt-transport-https
    mkdir -p /etc/apt/keyrings
    wget -q -O- https://downloads.opennebula.io/repo/repo2.key | gpg --dearmor --yes --output /etc/apt/keyrings/opennebula.gpg
    printf "%s\n" "deb [signed-by=/etc/apt/keyrings/opennebula.gpg] https://downloads.opennebula.io/repo/${OPENNEBULA_RELEASE}/Debian/12 stable opennebula" > /etc/apt/sources.list.d/opennebula.list
    apt-get update
    mkdir -p /var/cache/apt/archives
    apt-get -y --download-only --no-install-recommends install \
      ca-certificates python3 openssh-client qemu-utils libguestfs-tools virt-v2v \
      ovmf systemd-sysv gcc make opennebula-swap
    cp /var/cache/apt/archives/*.deb /bundle/debs/
    # Explicitly capture the resolved package metadata from the downloaded files.
    : > /bundle/packages.tsv
    for deb in /bundle/debs/*.deb; do
      dpkg-deb -f "$deb" Package Version Architecture | paste -sd "\t" - >> /bundle/packages.tsv
    done
    LC_ALL=C sort -u -o /bundle/packages.tsv /bundle/packages.tsv
  '

(
  cd "$bundle_dir"
  LC_ALL=C sha256sum debs/*.deb | LC_ALL=C sort > debs.sha256
  printf 'schema=1\nopennebula_release=%s\nresolver_image=%s\n' "$OPENNEBULA_RELEASE" "$RESOLVER_IMAGE" > bundle.meta
  tar --sort=name --mtime='UTC 1970-01-01' --owner=0 --group=0 --numeric-owner -czf "$OUTPUT" bundle.meta packages.tsv debs.sha256 debs
)

sha256sum "$OUTPUT" > "$OUTPUT.sha256"
printf 'offline_bundle=%s\n' "$OUTPUT"
printf 'offline_bundle_sha256=%s\n' "$(cut -d' ' -f1 "$OUTPUT.sha256")"
printf 'package_manifest=%s\n' "$bundle_dir/packages.tsv"
