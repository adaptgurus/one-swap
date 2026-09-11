# Hyper-V warm/hot migration durable state contract

This file is an implementation contract, not live qualification evidence.

## Phases

`PREPARED -> CUTOVER_STARTED -> SOURCE_OFF -> DELTA_APPLIED -> IMPORTED -> DONE`

### PREPARED

The source VM is still running. An application-consistent Hyper-V RCT reference point exists, its stable export has been transferred and SHA-256 verified, and `virt-v2v` has produced RAW prepared disks. Source VM identity/topology, target parameters, RCT IDs and prepared-disk sizes are durably recorded.

### CUTOVER_STARTED

Fresh pre-cutover checks passed. The operation has crossed the deliberate source-mutation boundary and is about to issue `Stop-VM -Shutdown`. Generic cleanup is forbidden from this point onward.

### SOURCE_OFF

The source VM is confirmed `Off`. The controller must not automatically restart it. Failures from this point require explicit reconciliation because source and prepared target state may have diverged.

### DELTA_APPLIED

`GetVirtualDiskChanges` ranges relative to the prepared RCT reference were read from the stopped source VHDX, transferred in checksummed bundles and patched into prepared RAW disks. `virt-v2v-in-place` has re-applied KVM guest morphing to the final disk contents.

### IMPORTED

OpenNebula Images/Template have been created. This is not migration success. LayerSentry must still instantiate the target with the durable migration marker and pass VM-state, network, recognizable-data checksum and no-dual-running validation.

### DONE

LayerSentry has independently validated migration success and post-success cleanup has destroyed the Hyper-V reference point/source staging state.

## Replay and failure rules

- `prepare` may return the existing `PREPARED` state for the same operation/VM/source profile; it must not create a second reference point.
- after `CUTOVER_STARTED`, no automatic source restart is permitted;
- source shutdown timeout is a failure and has no hard-poweroff fallback;
- final RCT or `virt-v2v-in-place` ambiguity keeps the source off and requires reconciliation;
- OpenNebula import partial failure is not safe to replay blindly;
- cleanup before cutover removes RCT/staging state; cleanup after cutover is refused;
- post-success cleanup is a distinct finalization step after target validation.
