#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
OPENNEBULA_RELEASE="${OPENNEBULA_RELEASE:-7.4.1}"
BASE_IMAGE="${BASE_IMAGE:?BASE_IMAGE must point to a Debian 12 generic-cloud QCOW2}"
BASE_IMAGE_SHA256="${BASE_IMAGE_SHA256:?BASE_IMAGE_SHA256 is required}"
VIRTIO_WIN_ISO="${VIRTIO_WIN_ISO:?VIRTIO_WIN_ISO is required}"
VIRTIO_WIN_SHA256="${VIRTIO_WIN_SHA256:?VIRTIO_WIN_SHA256 is required}"
OUTPUT="${OUTPUT:-$PWD/layersentry-oneswap-${OPENNEBULA_RELEASE}.qcow2}"
SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git -C "$ROOT_DIR" log -1 --format=%ct)}"
ONSWAP_COMMIT="$(git -C "$ROOT_DIR" rev-parse HEAD)"

for command in qemu-img virt-customize virt-cat sha256sum tar git; do
    command -v "$command" >/dev/null || { echo "missing required build tool: $command" >&2; exit 2; }
done

printf '%s  %s\n' "$BASE_IMAGE_SHA256" "$BASE_IMAGE" | sha256sum -c -
printf '%s  %s\n' "$VIRTIO_WIN_SHA256" "$VIRTIO_WIN_ISO" | sha256sum -c -

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
src_tar="$work/one-swap-source.tar.gz"
manifest="$work/build-manifest.json"

git -C "$ROOT_DIR" archive --format=tar.gz -o "$src_tar" HEAD
cat >"$manifest" <<EOF
{"schema":1,"opennebula_release":"$OPENNEBULA_RELEASE","oneswap_commit":"$ONSWAP_COMMIT","base_image_sha256":"$BASE_IMAGE_SHA256","virtio_win_sha256":"$VIRTIO_WIN_SHA256","source_date_epoch":$SOURCE_DATE_EPOCH}
EOF

cp --reflink=auto "$BASE_IMAGE" "$OUTPUT"
qemu-img resize "$OUTPUT" 32G >/dev/null

virt-customize -a "$OUTPUT" \
  --mkdir /opt/layersentry-build \
  --mkdir /usr/share/virtio-win \
  --upload "$src_tar:/opt/layersentry-build/one-swap-source.tar.gz" \
  --upload "$manifest:/opt/layersentry-build/build-manifest.json" \
  --upload "$VIRTIO_WIN_ISO:/usr/share/virtio-win/virtio-win.iso" \
  --run-command 'chmod 0644 /usr/share/virtio-win/virtio-win.iso' \
  --run-command 'export DEBIAN_FRONTEND=noninteractive; apt-get update; apt-get install -y --no-install-recommends ca-certificates gnupg wget apt-transport-https python3 openssh-client qemu-utils libguestfs-tools virt-v2v ovmf systemd-sysv' \
  --run-command 'mkdir -p /etc/apt/keyrings; wget -q -O- https://downloads.opennebula.io/repo/repo2.key | gpg --dearmor --yes --output /etc/apt/keyrings/opennebula.gpg' \
  --run-command "echo 'deb [signed-by=/etc/apt/keyrings/opennebula.gpg] https://downloads.opennebula.io/repo/${OPENNEBULA_RELEASE}/Debian/12 stable opennebula' > /etc/apt/sources.list.d/opennebula.list" \
  --run-command 'export DEBIAN_FRONTEND=noninteractive; apt-get update; apt-get install -y --no-install-recommends opennebula-swap' \
  --run-command "dpkg-query -W -f='\${Version}\n' opennebula-swap | grep -E '^${OPENNEBULA_RELEASE}([.-]|$)'" \
  --run-command 'mkdir -p /opt/layersentry-build/src; tar -xzf /opt/layersentry-build/one-swap-source.tar.gz -C /opt/layersentry-build/src' \
  --run-command 'cd /opt/layersentry-build/src && make && ./install.sh && ./appliance/install-appliance.sh /opt/layersentry-build/src' \
  --run-command 'cp /opt/layersentry-build/build-manifest.json /var/lib/layersentry-oneswap/build-manifest.json' \
  --run-command "printf '%s\n' '$ONSWAP_COMMIT' > /var/lib/layersentry-oneswap/oneswap-commit" \
  --run-command 'dpkg-query -W -f="${Package}\t${Version}\t${Architecture}\n" | LC_ALL=C sort > /var/lib/layersentry-oneswap/sbom-packages.tsv' \
  --run-command 'rm -rf /opt/layersentry-build/src /opt/layersentry-build/one-swap-source.tar.gz' \
  --run-command 'apt-get clean; rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*' \
  --run-command 'systemctl disable oneswapd.service || true' \
  --run-command 'cloud-init clean --logs --machine-id || true'

qemu-img check "$OUTPUT"
virt-cat -a "$OUTPUT" /var/lib/layersentry-oneswap/build-manifest.json > "$OUTPUT.manifest.json"
virt-cat -a "$OUTPUT" /var/lib/layersentry-oneswap/sbom-packages.tsv > "$OUTPUT.sbom.tsv"
sha256sum "$OUTPUT" > "$OUTPUT.sha256"

printf 'appliance=%s\n' "$OUTPUT"
printf 'sha256_file=%s\n' "$OUTPUT.sha256"
printf 'manifest=%s\n' "$OUTPUT.manifest.json"
printf 'sbom=%s\n' "$OUTPUT.sbom.tsv"
