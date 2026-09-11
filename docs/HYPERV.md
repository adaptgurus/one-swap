# Hyper-V to OpenNebula migration

`oneswap-hyperv` provides a production-oriented **cold** migration path from Microsoft Hyper-V to OpenNebula/KVM.

## Safety boundary

The first qualified source path is deliberately cold-only. Before any disk transfer the source VM must be `Off`. The command fails closed when the VM has checkpoints/differencing disks, Discrete Device Assignment, shielding, or vTPM. Those features need topology/security-specific migration work and are not silently discarded.

The Hyper-V connection uses OpenSSH public-key authentication only. `StrictHostKeyChecking=yes`, a pinned `known_hosts` file, `BatchMode=yes`, and `PasswordAuthentication=no` are mandatory. Passwords and private-key contents are never command-line parameters.

Every source VHD/VHDX is SHA-256 hashed on Hyper-V, streamed to the conversion host, size checked, and SHA-256 verified locally before conversion. `virt-v2v` is then used to morph the guest for KVM. The existing OneSwap image path performs guest inspection/context/VirtIO/QEMU Guest Agent handling and creates OpenNebula Images. A VM Template is created with CPU/RAM, Generation 1/2 firmware, Secure Boot, disks, NIC/MAC mapping, and optional OpenNebula placement constraints.

A successful OneSwap process means Images/Template were created. LayerSentry must still instantiate and validate the target VM before the overall migration becomes successful.

## Server-side connection profile

Prefer a named server-owned connection profile rather than passing source infrastructure paths through a customer request:

```yaml
:hyperv_connections:
  hv-prod:
    host: hv01.example.com
    user: Administrator
    port: 22
    identity_file: /etc/one/oneswap/hyperv/hv-prod.key
    known_hosts: /etc/one/oneswap/hyperv/known_hosts
```

The identity file must not be readable by group/other users.

## Example

```bash
oneswap-hyperv windows-app-01 \
  --hyperv-connection hv-prod \
  --datastore 101 \
  --network 220 \
  --one-cluster 12 \
  --virtio /usr/share/virtio-win/virtio-win.iso \
  --win-qemu-ga /usr/share/virtio-win/virtio-win.iso
```

For multiple source NICs, `--network` accepts one OpenNebula VNet ID for all NICs or a comma-separated list with exactly one target VNet per source NIC. Hyper-V MAC addresses are retained unless `--skip-mac` is selected.

## Preconditions on the Hyper-V host

OpenSSH Server must be enabled for the migration account and PowerShell Hyper-V cmdlets must be available. The account needs read access to the VM configuration/VHD files and permission to execute `Get-VM`, `Get-VHD`, `Get-VMSnapshot`, `Get-VMHardDiskDrive`, `Get-VMNetworkAdapter`, `Get-VMSecurity`, and (for Generation 2) `Get-VMFirmware`.

## Not yet qualified

Warm/delta Hyper-V migration, checkpoint-chain migration, shielded VM migration, vTPM/BitLocker-bound security state, DDA device transfer, and live cross-hypervisor migration are not claimed by this source increment. They remain blocked until implementation plus real Hyper-V/OpenNebula evidence exists.
