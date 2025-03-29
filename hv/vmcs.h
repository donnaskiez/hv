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

#endif