#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
OPENNEBULA_RELEASE="${OPENNEBULA_RELEASE:-7.4.1}"
BASE_IMAGE="${BASE_IMAGE:?BASE_IMAGE must point to a pinned Debian 12 generic-cloud QCOW2}"
BASE_IMAGE_SHA256="${BASE_IMAGE_SHA256:?BASE_IMAGE_SHA256 is required}"
VIRTIO_WIN_ISO="${VIRTIO_WIN_ISO:?VIRTIO_WIN_ISO is required}"
VIRTIO_WIN_SHA256="${VIRTIO_WIN_SHA256:?VIRTIO_WIN_SHA256 is required}"
OFFLINE_BUNDLE="${OFFLINE_BUNDLE:?OFFLINE_BUNDLE must point to the qualified package bundle}"
OFFLINE_BUNDLE_SHA256="${OFFLINE_BUNDLE_SHA256:?OFFLINE_BUNDLE_SHA256 is required}"
OUTPUT="${OUTPUT:-$PWD/layersentry-oneswap-${OPENNEBULA_RELEASE}.qcow2}"
SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git -C "$ROOT_DIR" log -1 --format=%ct)}"
ONSWAP_COMMIT="$(git -C "$ROOT_DIR" rev-parse HEAD)"

for command in qemu-img virt-resize virt-customize virt-cat sha256sum tar git; do
    command -v "$command" >/dev/null || { echo "missing required build tool: $command" >&2; exit 2; }
done

printf '%s  %s\n' "$BASE_IMAGE_SHA256" "$BASE_IMAGE" | sha256sum -c -
printf '%s  %s\n' "$VIRTIO_WIN_SHA256" "$VIRTIO_WIN_ISO" | sha256sum -c -
printf '%s  %s\n' "$OFFLINE_BUNDLE_SHA256" "$OFFLINE_BUNDLE" | sha256sum -c -

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
src_tar="$work/one-swap-source.tar.gz"
manifest="$work/build-manifest.json"
bundle_check="$work/bundle-check"
mkdir -p "$bundle_check"

tar -xzf "$OFFLINE_BUNDLE" -C "$bundle_check"
for required in bundle.meta packages.tsv resolved-installed.tsv Packages Packages.gz debs.sha256 debs; do
    test -e "$bundle_check/$required" || { echo "offline bundle is missing $required" >&2; exit 3; }
done
grep -q $'^opennebula-swap\t' "$bundle_check/packages.tsv" || { echo "offline bundle does not contain opennebula-swap" >&2; exit 3; }
grep -q '^schema=2$' "$bundle_check/bundle.meta" || { echo "offline bundle schema mismatch" >&2; exit 3; }
grep -q "^opennebula_release=${OPENNEBULA_RELEASE}$" "$bundle_check/bundle.meta" || { echo "offline bundle OpenNebula release mismatch" >&2; exit 3; }
grep -q '^Filename: debs/' "$bundle_check/Packages" || { echo "offline bundle APT index is invalid" >&2; exit 3; }
(
    cd "$bundle_check"
    sha256sum -c debs.sha256
)

git -C "$ROOT_DIR" archive --format=tar.gz -o "$src_tar" HEAD
cat >"$manifest" <<EOF
{"schema":2,"opennebula_release":"$OPENNEBULA_RELEASE","oneswap_commit":"$ONSWAP_COMMIT","base_image_sha256":"$BASE_IMAGE_SHA256","virtio_win_sha256":"$VIRTIO_WIN_SHA256","offline_bundle_sha256":"$OFFLINE_BUNDLE_SHA256","source_date_epoch":$SOURCE_DATE_EPOCH}
EOF

# qemu-img resize changes only the virtual container size; it does not grow
# the root partition/filesystem. Build a fresh 32 GiB destination and let
# virt-resize expand the pinned Debian generic-cloud root partition.
rm -f "$OUTPUT"
qemu-img create -f qcow2 "$OUTPUT" 32G >/dev/null
virt-resize --expand /dev/sda1 "$BASE_IMAGE" "$OUTPUT"

# --no-network is intentional. Package resolution uses only the immutable
# file:// APT repository embedded in OFFLINE_BUNDLE; all normal APT source
# files and source-parts are excluded from both update and install.
virt-customize --no-network -a "$OUTPUT" \
  --mkdir /opt/layersentry-build \
  --mkdir /usr/share/virtio-win \
  --upload "$src_tar:/opt/layersentry-build/one-swap-source.tar.gz" \
  --upload "$manifest:/opt/layersentry-build/build-manifest.json" \
  --upload "$OFFLINE_BUNDLE:/opt/layersentry-build/packages.tar.gz" \
  --upload "$VIRTIO_WIN_ISO:/usr/share/virtio-win/virtio-win.iso" \
  --run-command 'chmod 0644 /usr/share/virtio-win/virtio-win.iso' \
  --run-command 'mkdir -p /opt/layersentry-build/packages; tar -xzf /opt/layersentry-build/packages.tar.gz -C /opt/layersentry-build/packages' \
  --run-command 'cd /opt/layersentry-build/packages && sha256sum -c debs.sha256' \
  --run-command 'mkdir -p /run/lock; chmod 0755 /run/lock; if [ ! -L /var/lock ]; then test ! -e /var/lock; ln -s ../run/lock /var/lock; fi; test -d /var/lock' \
  --run-command 'printf "%s\n" "deb [trusted=yes] file:/opt/layersentry-build/packages ./" > /opt/layersentry-build/offline.list' \
  --run-command 'export DEBIAN_FRONTEND=noninteractive; apt-get -o Dir::Etc::sourcelist=/opt/layersentry-build/offline.list -o Dir::Etc::sourceparts=- -o Acquire::Languages=none update' \
  --run-command 'export DEBIAN_FRONTEND=noninteractive; set --; while IFS="$(printf "\t")" read -r package version architecture; do [ -n "$package" ] || continue; set -- "$@" "${package}=${version}"; done < /opt/layersentry-build/packages/resolved-installed.tsv; [ "$#" -gt 0 ]; apt-get -y --no-install-recommends --allow-downgrades -o Dir::Etc::sourcelist=/opt/layersentry-build/offline.list -o Dir::Etc::sourceparts=- -o Acquire::Languages=none install "$@"' \
  --run-command 'dpkg --audit; apt-get -o Dir::Etc::sourcelist=/opt/layersentry-build/offline.list -o Dir::Etc::sourceparts=- check' \
  --run-command "dpkg-query -W -f='\${Version}\n' opennebula-swap | grep -E '^${OPENNEBULA_RELEASE}([.+~-]|$)'" \
  --run-command 'mkdir -p /opt/layersentry-build/src; tar -xzf /opt/layersentry-build/one-swap-source.tar.gz -C /opt/layersentry-build/src' \
  --run-command 'cd /opt/layersentry-build/src && make && ./install.sh && ./appliance/install-appliance.sh /opt/layersentry-build/src' \
  --run-command 'cp /opt/layersentry-build/build-manifest.json /var/lib/layersentry-oneswap/build-manifest.json' \
  --run-command 'cp /opt/layersentry-build/packages/packages.tsv /var/lib/layersentry-oneswap/qualified-packages.tsv' \
  --run-command 'cp /opt/layersentry-build/packages/debs.sha256 /var/lib/layersentry-oneswap/qualified-debs.sha256' \
  --run-command "printf '%s\n' '$ONSWAP_COMMIT' > /var/lib/layersentry-oneswap/oneswap-commit" \
  --run-command 'dpkg-query -W -f="\${Package}\t\${Version}\t\${Architecture}\n" | LC_ALL=C sort > /var/lib/layersentry-oneswap/sbom-packages.tsv' \
  --run-command 'rm -rf /opt/layersentry-build/src /opt/layersentry-build/one-swap-source.tar.gz /opt/layersentry-build/packages /opt/layersentry-build/packages.tar.gz; rm -f /opt/layersentry-build/offline.list' \
  --run-command 'rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*' \
  --run-command 'systemctl disable oneswapd.service || true' \
  --run-command 'cloud-init clean --logs --machine-id || true'

qemu-img check "$OUTPUT"
virt-cat -a "$OUTPUT" /var/lib/layersentry-oneswap/build-manifest.json > "$OUTPUT.manifest.json"
virt-cat -a "$OUTPUT" /var/lib/layersentry-oneswap/sbom-packages.tsv > "$OUTPUT.sbom.tsv"
virt-cat -a "$OUTPUT" /var/lib/layersentry-oneswap/qualified-packages.tsv > "$OUTPUT.qualified-packages.tsv"
virt-cat -a "$OUTPUT" /var/lib/layersentry-oneswap/qualified-debs.sha256 > "$OUTPUT.qualified-debs.sha256"
sha256sum "$OUTPUT" > "$OUTPUT.sha256"

printf 'appliance=%s\n' "$OUTPUT"
printf 'sha256_file=%s\n' "$OUTPUT.sha256"
printf 'manifest=%s\n' "$OUTPUT.manifest.json"
printf 'sbom=%s\n' "$OUTPUT.sbom.tsv"
printf 'qualified_packages=%s\n' "$OUTPUT.qualified-packages.tsv"
