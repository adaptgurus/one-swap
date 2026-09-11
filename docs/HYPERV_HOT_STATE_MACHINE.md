# Hyper-V warm/hot migration durable state contract

This file is an implementation contract, not live qualification evidence.

## Phases

`PREPARED -> CUTOVER_STARTED -> SOURCE_OFF -> MORPHING -> DELTA_APPLIED -> IMPORTING -> IMPORTED -> DONE`

### PREPARED

The source VM is still running. An application-consistent Hyper-V RCT reference point exists, its stable export has been transferred and SHA-256 verified, and `qemu-img` has created block-layout-preserving RAW baseline mirrors. Source VM identity/topology, target parameters, RCT IDs and prepared-disk sizes are durably recorded.

### CUTOVER_STARTED

Fresh pre-cutover checks passed. The operation has crossed the deliberate source-mutation boundary and is about to issue `Stop-VM -Shutdown`. Generic cleanup is forbidden from this point onward.

### SOURCE_OFF

The source VM is confirmed `Off`. The controller must not automatically restart it. Failures from this point require explicit reconciliation because source and prepared target state may have diverged.

### MORPHING

Final RCT changed-byte bundles have been applied to the unmodified RAW baseline and `virt-v2v-in-place` has been dispatched. This is an ambiguity barrier: if execution is interrupted, automatic replay is prohibited because the target disks may have been partially modified.

### DELTA_APPLIED

The final source delta has been applied and `virt-v2v-in-place` completed successfully. The final RAW guest is ready for OpenNebula import.

### IMPORTING

OpenNebula Image/Template creation has been dispatched. This is an ambiguity barrier: an interruption can leave partial provider artifacts, so the operation must not blindly allocate them again.

### IMPORTED

OpenNebula Images/Template have been created. This is not migration success. LayerSentry must still instantiate the target with the durable migration marker and pass VM-state, network, recognizable-data checksum and no-dual-running validation.

### DONE

LayerSentry has independently validated migration success and post-success cleanup has destroyed the Hyper-V reference point/source staging state. Repeating the finalizer in `DONE` is an idempotent no-op.

## Replay and failure rules

- `prepare` may return the existing `PREPARED` state for the same operation/VM/source profile; it must not create a second reference point;
- RCT byte offsets are applied before guest morphing, never to a disk already modified by `virt-v2v`;
- an asynchronous `GetVirtualDiskChanges` response is not retried as a second RCT query; the current source fails closed until authoritative async output recovery is qualified;
- after `CUTOVER_STARTED`, no automatic source restart is permitted;
- source shutdown timeout is a failure and has no hard-poweroff fallback;
- source state is rechecked as `Off` before final RCT ranges are read;
- `MORPHING` and `IMPORTING` prohibit blind automatic replay;
- OpenNebula partial import requires reconciliation rather than duplicate allocation;
- cleanup before cutover is allowed only in `PREPARED`; cleanup after cutover is refused;
- post-success cleanup is a distinct idempotent finalization step after target validation.
