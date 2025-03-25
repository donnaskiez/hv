#ifndef VMCS_H
#define VMCS_H

#include "common.h"
#include "vmx.h"

NTSTATUS
HvVmcsInitialise(_In_ PVCPU GuestState, _In_ PVOID StackPointer);

UINT64
HvVmcsRead(_In_ UINT64 VmcsField);

VOID
HvVmcsWrite(_In_ UINT64 VmcsField, _In_ UINT64 Value);

UINT64
HvVmxGuestReadRip();

UINT64
HvVmxGuestReadRsp();

UINT64
HvVmxGetVcpu();

BOOLEAN
HvVmcsIsApicPresent();

#endif