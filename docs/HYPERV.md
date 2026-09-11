# Hyper-V to OpenNebula migration

`oneswap-hyperv` supports two source paths:

1. **Cold conversion**: source VM is already `Off`, whole VHD/VHDX files are copied and converted.
2. **Warm/hot pre-copy with final cutover**: source VM remains `Running` during the long baseline copy/conversion. Hyper-V Resilient Change Tracking (RCT) is used to identify changes after the baseline. Immediately before final migration the source is revalidated and gracefully shut down, only the final changed guest byte ranges are transferred/applied, then the prepared guest is re-morphed and imported into OpenNebula.

The hot path is not a claim that the same VM executes simultaneously on Hyper-V and OpenNebula. It is a warm pre-copy design with a short **source-off final cutover**.

## Hot migration sequence

```text
non-mutating preflight
  -> source VM RUNNING
  -> capability/topology checks
  -> application-consistent RCT reference point
  -> export stable reference point while VM keeps running
  -> copy/verify baseline VHDX
  -> virt-v2v to prepared RAW disks
  -> AWAITING_CUTOVER
  -> fresh pre-cutover validation
  -> graceful Stop-VM -Shutdown
  -> wait for source Off
  -> GetVirtualDiskChanges using prepared RCT IDs
  -> read changed guest byte ranges from read-only mounted VHDX
  -> transfer SHA-256 protected delta bundles
  -> patch prepared RAW disks by guest offset
  -> virt-v2v-in-place against the final RAW multi-disk guest
  -> allocate OpenNebula Images and Template
  -> LayerSentry native VM materialization
  -> VM/network/recognizable-data/no-dual-running validation
  -> cleanup RCT reference point only after validated success
```

## Why RCT instead of copying AVHDX

The hot path does **not** copy Hyper-V `.avhdx` differencing chains into QEMU. It uses the Windows Server 2016+ Hyper-V reference-point/RCT APIs and `GetVirtualDiskChanges` to retrieve guest-visible changed ranges. This keeps Hyper-V authoritative for the changed-block map and avoids treating an unsupported differencing VHDX chain as a normal QEMU input.

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
- `virt-v2v` and `virt-v2v-in-place` installed;
- Generation 2 UEFI/Secure Boot firmware path available/configured.

The prepare phase requests an **application-consistent** RCT reference point. There is no silent fallback to crash-consistent migration.

## Mandatory pre-cutover revalidation

The final shutdown is not issued merely because prepare completed. Immediately before cutover OneSwap rechecks:

- same Hyper-V VM ID;
- source still `Running`;
- same CPU/memory/generation;
- same disk paths, VirtualDisk IDs, virtual sizes and controller order;
- same NIC/MAC/switch/VLAN topology;
- no new checkpoints, DDA, GPU-P, vFC, vTPM, shielding or nested virtualization;
- RCT reference point still exists;
- target datastore/network parameters have not changed;
- target OpenNebula resources still resolve;
- every prepared RAW disk exists with the expected virtual size.

Any drift blocks cutover and leaves the source running.

## Final shutdown policy

`--commit` uses `Stop-VM -Shutdown` and waits for state `Off`. The default source does **not** fall back to `-TurnOff`. If graceful shutdown does not complete within the configured timeout, cutover fails without an automatic hard power-off.

After `CUTOVER_STARTED`/`SOURCE_OFF`, OneSwap will never automatically restart the Hyper-V source. A failure after this boundary must be reconciled explicitly to avoid dual running or data divergence.

## Durable hot state

Hot operations require `--operation-id`. OneSwap stores owner-only state in:

```text
<work-dir>/oneswap-hyperv-hot/<operation-id>/state.json
```

The state machine is:

```text
PREPARED -> CUTOVER_STARTED -> SOURCE_OFF -> DELTA_APPLIED -> IMPORTED -> DONE
```

`--cleanup` is allowed only while `PREPARED`. After cutover starts, cleanup refuses to delete evidence. `--finalize-success` removes the RCT reference/staging only after LayerSentry has independently validated target success.

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

Baseline exported VHDX and final delta bundles are SHA-256 checked across the SSH transfer. This proves source-to-conversion-host transport integrity. It does **not** replace LayerSentry's post-boot recognizable guest-data validation. Overall migration success still requires target VM state, target networking, configured data checksum and no-dual-running validation.

## Still unsupported / not certified

The source code intentionally blocks checkpoint-chain migration, shielded/vTPM migration, DDA, GPU-P, virtual Fibre Channel and nested-virtualization guests. True zero-downtime cross-hypervisor live execution is not claimed. Production certification also requires real Hyper-V/OpenNebula testing for Generation 1/2, Windows/Linux boot, VirtIO, multi-disk/NIC, Secure Boot, large VHDX, RCT correctness, interrupted prepare/commit, controller restart, source shutdown failure, partial OpenNebula import, target data integrity and no-dual-running proof.
