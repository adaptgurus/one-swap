# Hyper-V to OpenNebula migration

`oneswap-hyperv` supports two source paths:

1. **Cold conversion**: source VM is already `Off`, whole VHD/VHDX files are copied and converted.
2. **Warm/hot pre-copy with final cutover**: source VM remains `Running` during the long baseline copy. Hyper-V Resilient Change Tracking (RCT) identifies changes after the baseline. Immediately before final migration the source is revalidated and gracefully shut down, only the final changed guest byte ranges are transferred/applied, then the final guest is morphed for KVM and imported into OpenNebula.

The hot path is not a claim that the same VM executes simultaneously on Hyper-V and OpenNebula. It is a warm pre-copy design with a short **source-off final cutover**.

## Hot migration sequence

```text
non-mutating preflight
  -> source VM RUNNING
  -> capability/topology checks
  -> application-consistent RCT reference point
  -> export stable reference point while VM keeps running
  -> copy/verify baseline VHDX
  -> qemu-img VHDX -> RAW (layout-preserving baseline mirror)
  -> AWAITING_CUTOVER
  -> fresh pre-cutover validation
  -> graceful Stop-VM -Shutdown
  -> wait for source Off
  -> GetVirtualDiskChanges using prepared RCT IDs
  -> read changed guest byte ranges from read-only mounted source VHDX
  -> transfer SHA-256 protected delta bundles
  -> patch the unmodified RAW baseline by guest offset
  -> virt-v2v-in-place once against the final RAW multi-disk guest
  -> allocate OpenNebula Images and Template
  -> LayerSentry native VM materialization
  -> VM/network/recognizable-data/no-dual-running validation
  -> LayerSentry calls --finalize-success
  -> cleanup RCT reference point/source staging
```

The prepare phase deliberately does **not** run `virt-v2v`. RCT offsets describe the source virtual-disk address space, so they must be applied to a block-layout-preserving RAW mirror. Applying source RCT ranges to a disk that `virt-v2v` had already modified could overwrite conversion changes. The hardened flow therefore morphs the guest only after the final RCT delta has been applied.

## Why RCT instead of copying AVHDX

The hot path does **not** copy Hyper-V `.avhdx` differencing chains into QEMU. It uses the Windows Server 2016+ Hyper-V reference-point/RCT APIs and `GetVirtualDiskChanges` to retrieve guest-visible changed ranges. This keeps Hyper-V authoritative for the changed-block map and avoids treating a differencing VHDX chain as a normal QEMU input.

If `GetVirtualDiskChanges` returns an asynchronous WMI job (`4096`), the source currently fails closed. It does not issue a second RCT query, because doing so would be a replay rather than authoritative recovery of the original job's output parameters. Asynchronous-result recovery requires separate live qualification before it can be enabled.

## Mandatory hot preflight

Before creating a reference point, all of the following must pass:

- Windows Server 2016+ / build 14393+;
- `Msvm_VirtualSystemReferencePointService` and `Msvm_ImageManagementService` available;
- source VM exactly `Running`;
- Generation 1 or Generation 2;
- only flat fixed/dynamic **VHDX** source disks; no parent/differencing chain;
- no existing or automatic Hyper-V checkpoints;
- no Discrete Device Assignment;
- no GPU-P partition adapter;
- no virtual Fibre Channel HBA;
- no exposed nested virtualization extensions;
- no shielded VM or vTPM;
- existing source-host staging directory with enough free space;
- explicit OpenNebula Image Datastore;
- target VNet mapping for every source NIC;
- target OpenNebula datastore/VNets resolvable through the selected tenant identity;
- local conversion workspace with conservative capacity for baseline download plus RAW prepared disks;
- `qemu-img`, `virt-v2v` and `virt-v2v-in-place` installed;
- Generation 2 UEFI/Secure Boot firmware path available/configured.

The prepare phase requests an **application-consistent** RCT reference point. There is no silent fallback to crash-consistent migration.

## Mandatory pre-cutover revalidation

The final shutdown is not issued merely because prepare completed. Immediately before cutover OneSwap rechecks:

- same Hyper-V VM ID;
- source still `Running`;
- same CPU/memory/generation;
- same disk paths, VirtualDisk IDs, virtual sizes and controller order;
- same NIC/MAC/switch and complete VLAN topology, including access, trunk allowed/native and PVLAN fields;
- no new checkpoints, DDA, GPU-P, vFC, vTPM, shielding or nested virtualization;
- RCT reference point still exists;
- target datastore/network parameters have not changed;
- target OpenNebula resources still resolve;
- every prepared RAW disk exists with the expected virtual size.

Any drift blocks cutover and leaves the source running.

## Final shutdown policy

`--commit` uses `Stop-VM -Shutdown` and waits for state `Off`. The source does **not** fall back to `-TurnOff`. If graceful shutdown does not complete within the configured timeout, cutover fails without an automatic hard power-off.

After `CUTOVER_STARTED`/`SOURCE_OFF`, OneSwap will never automatically restart the Hyper-V source. A failure after this boundary must be reconciled explicitly to avoid dual running or data divergence.

## Durable hot state

Hot operations require `--operation-id`. The owner-only state directory contains a sanitized operation label plus a SHA-256-derived suffix so two different valid operation IDs cannot collide on disk:

```text
<work-dir>/oneswap-hyperv-hot/<safe-operation-id>-<digest>/state.json
```

Normal progression is:

```text
PREPARED
  -> CUTOVER_STARTED
  -> SOURCE_OFF
  -> MORPHING
  -> DELTA_APPLIED
  -> IMPORTING
  -> IMPORTED
  -> DONE
```

`MORPHING` and `IMPORTING` are intentional ambiguity barriers. If a process/controller dies in either phase, a subsequent `--commit` refuses blind replay because `virt-v2v-in-place` or OpenNebula allocation may already have partially changed target state. Reconciliation is required.

`--cleanup` is allowed only while `PREPARED`. After cutover starts, cleanup refuses to delete evidence. `--finalize-success` removes the RCT reference/source staging only after LayerSentry has independently validated target success. LayerSentry production runtime invokes that finalizer automatically after VM/network/data/no-dual-running validation; finalizer failure keeps the migration out of `SUCCESS` until cleanup is reconciled.

## Server-side connection profile

Prefer a server-owned profile:

```yaml
:hyperv_connections:
  hv-prod:
    host: hv01.example.com
    user: Administrator
    port: 22
    identity_file: /etc/one/oneswap/hyperv/hv-prod.key
    known_hosts: /etc/one/oneswap/hyperv/known_hosts
    staging_dir: D:\\LayerSentryMigration
    shutdown_timeout: 300
    transfer_timeout: 7200
    prepare_timeout: 7200
    delta_timeout: 7200
```

SSH uses public-key authentication only with `BatchMode=yes`, `IdentitiesOnly=yes`, `StrictHostKeyChecking=yes`, pinned `known_hosts`, and `PasswordAuthentication=no`.

## Hot CLI phases

Non-mutating source/target capability check:

```bash
oneswap-hyperv windows-app-01 --hot --preflight \
  --operation-id mig-123 --hyperv-connection hv-prod \
  --datastore 101 --network 220 --one-cluster 12
```

Prepare while the VM remains running:

```bash
oneswap-hyperv windows-app-01 --hot --prepare \
  --operation-id mig-123 --hyperv-connection hv-prod \
  --datastore 101 --network 220 --one-cluster 12
```

Final cutover after approval:

```bash
oneswap-hyperv windows-app-01 --hot --commit \
  --operation-id mig-123 --hyperv-connection hv-prod \
  --datastore 101 --network 220 --one-cluster 12
```

Abort a prepared migration before cutover:

```bash
oneswap-hyperv windows-app-01 --hot --cleanup \
  --operation-id mig-123 --hyperv-connection hv-prod \
  --datastore 101 --network 220
```

The target datastore/network/placement arguments must remain identical between prepare and commit; their digest is stored in durable state.

## Integrity boundaries

Baseline exported VHDX and final delta bundles are SHA-256 checked across the SSH transfer. The prepared RAW disk is an exact virtual-block mirror before the final delta is patched. This proves source-to-conversion-host transport/layout integrity. It does **not** replace LayerSentry's post-boot recognizable guest-data validation. Overall migration success still requires target VM state, target networking, configured data checksum and no-dual-running validation.

## Still unsupported / not certified

The source code intentionally blocks checkpoint-chain migration, shielded/vTPM migration, DDA, GPU-P, virtual Fibre Channel and nested-virtualization guests. True zero-downtime cross-hypervisor live execution is not claimed.

A crash in `IMPORTING` is deliberately not auto-replayed yet because one or more OpenNebula Images may already exist. The ambiguity barrier prevents duplicate allocation/data corruption, but automated partial-Image adoption remains a live-qualification/integration item.

Production certification still requires real Hyper-V/OpenNebula testing for Generation 1/2, Windows/Linux boot, VirtIO, multi-disk/NIC, Secure Boot, large VHDX, RCT correctness, synchronous/asynchronous RCT behavior on the qualified Windows builds, interrupted prepare/commit, controller restart, source shutdown failure, partial OpenNebula import recovery, target data integrity and no-dual-running proof.
