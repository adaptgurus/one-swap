#!/usr/bin/env bash
set -euo pipefail

# Qualification-time resolver only. The production QCOW2 builder never talks
# to package repositories; it consumes only this immutable, hashed bundle.
RESOLVER_IMAGE="${RESOLVER_IMAGE:?RESOLVER_IMAGE must be an immutable debian:12@sha256:... reference}"
OPENNEBULA_RELEASE="${OPENNEBULA_RELEASE:-7.4.1}"
OUTPUT="${OUTPUT:-$PWD/layersentry-oneswap-packages-${OPENNEBULA_RELEASE}.tar.gz}"
case "$OUTPUT" in
  /*) ;;
  *) OUTPUT="$PWD/$OUTPUT" ;;
esac
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

case "$RESOLVER_IMAGE" in
  *@sha256:*) ;;
  *) echo "RESOLVER_IMAGE must be pinned by sha256 digest" >&2; exit 2 ;;
esac

command -v docker >/dev/null || { echo "docker is required to resolve the offline package closure" >&2; exit 2; }
command -v sha256sum >/dev/null || { echo "sha256sum is required" >&2; exit 2; }

bundle_dir="$WORK/bundle"
resolver_script="$WORK/resolve-inside.sh"
mkdir -p "$bundle_dir/debs"

cat > "$resolver_script" <<'INSIDE'
#!/usr/bin/env bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get install -y --no-install-recommends ca-certificates gnupg wget apt-transport-https
mkdir -p /etc/apt/keyrings
wget -q -O- https://downloads.opennebula.io/repo/repo2.key | gpg --dearmor --yes --output /etc/apt/keyrings/opennebula.gpg
printf '%s\n' "deb [signed-by=/etc/apt/keyrings/opennebula.gpg] https://downloads.opennebula.io/repo/${OPENNEBULA_RELEASE}/Debian/12 stable opennebula" > /etc/apt/sources.list.d/opennebula.list
apt-get update
apt-get install -y --no-install-recommends \
  ca-certificates python3 openssh-client qemu-utils libguestfs-tools virt-v2v \
  ovmf systemd-sysv gcc make opennebula-swap

dpkg-query -W -f='${binary:Package}\t${Version}\t${Architecture}\n' | LC_ALL=C sort > /bundle/resolved-installed.tsv
cd /bundle/debs
while IFS=$'\t' read -r package version architecture; do
  apt-get download "${package}=${version}"
done < /bundle/resolved-installed.tsv

: > /bundle/packages.tsv
for deb in /bundle/debs/*.deb; do
  dpkg-deb -f "$deb" Package Version Architecture | paste -sd $'\t' - >> /bundle/packages.tsv
done
LC_ALL=C sort -u -o /bundle/packages.tsv /bundle/packages.tsv
grep -Eq '^opennebula-swap[[:space:]]' /bundle/packages.tsv
INSIDE
chmod 0755 "$resolver_script"

# Install the target toolchain inside the immutable resolver container, then
# download every installed package at its exact version. This deliberately
# over-captures the closure so the final guest build can run with networking
# disabled and --no-download, without trusting the base image to provide a
# dependency at an unspecified version.
docker run --rm \
  -e OPENNEBULA_RELEASE="$OPENNEBULA_RELEASE" \
  -v "$bundle_dir:/bundle" \
  -v "$resolver_script:/resolve-inside.sh:ro" \
  "$RESOLVER_IMAGE" /bin/bash /resolve-inside.sh

(
  cd "$bundle_dir"
  LC_ALL=C sha256sum debs/*.deb | LC_ALL=C sort > debs.sha256
  printf 'schema=1\nopennebula_release=%s\nresolver_image=%s\n' "$OPENNEBULA_RELEASE" "$RESOLVER_IMAGE" > bundle.meta
  tar --sort=name --mtime='UTC 1970-01-01' --owner=0 --group=0 --numeric-owner \
    -czf "$OUTPUT" bundle.meta packages.tsv resolved-installed.tsv debs.sha256 debs
)

sha256sum "$OUTPUT" > "$OUTPUT.sha256"
printf 'offline_bundle=%s\n' "$OUTPUT"
printf 'offline_bundle_sha256=%s\n' "$(cut -d' ' -f1 "$OUTPUT.sha256")"
printf 'resolved_packages=%s\n' "$bundle_dir/packages.tsv"
