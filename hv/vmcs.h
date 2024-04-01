#ifndef VMCS_H
#define VMCS_H

#include "common.h"
#include "vmx.h"

NTSTATUS
SetupVmcs(_In_ PVIRTUAL_MACHINE_STATE GuestState, _In_ PVOID StackPointer);

UINT64
VmxVmRead(_In_ UINT64 VmcsField);

VOID
VmxVmWrite(_In_ UINT64 VmcsField, _In_ UINT64 Value);

UINT64
VmmReadGuestRip();

UINT64
VmmReadGuestRsp();

UINT64
VmmGetCoresVcpu();

BOOLEAN
IsLocalApicPresent();

#endif