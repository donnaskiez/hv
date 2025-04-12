#ifndef VMCS_H
#define VMCS_H

#include "common.h"

#include "vmx.h"

#define HV_GUEST_CPL_KERNEL 0
#define HV_GUEST_CPL_USER 3

UINT16
HvVmcsGuestGetProtectionLevel();

NTSTATUS
HvVmcsInitialise(_In_ PVCPU GuestState, _In_ PVOID StackPointer);

UINT64
HvVmcsRead(_In_ UINT64 VmcsField);

VOID
HvVmcsWrite64(_In_ UINT64 VmcsField, _In_ UINT64 Value);

VOID
HvVmcsWrite32(_In_ UINT64 VmcsField, _In_ UINT32 Value);

UINT64
HvVmxGuestReadRip();

UINT64
HvVmxGuestReadRsp();

PVCPU
HvVmxGetVcpu();

BOOLEAN
HvVmcsIsApicPresent();

VOID
HvVmcsWritePrimaryProcessorControls(_In_ PVCPU Vcpu);

VOID
HvVmcsWriteSecondaryProcessControls(_In_ PVCPU Vcpu);

VOID
HvVmcsWritePinBasedControls(_In_ PVCPU Vcpu);

VOID
HvVmcsWriteExitControls(_In_ PVCPU Vcpu);

VOID
HvVmcsWriteEntryControls(_In_ PVCPU Vcpu);

VOID
HvVmcsWriteExceptionBitmap(_In_ PVCPU Vcpu);

VOID
HvVmcsWriteMsrBitmap(_In_ PVCPU Vcpu);

VOID
HvVmcsSyncConfiguration(_In_ PVCPU Vcpu);

VOID
HvVmcsPropagateUpdate(_In_ PVCPU Vcpu, _In_ UINT32 Update);

#endif