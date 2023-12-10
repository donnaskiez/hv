#ifndef VMCS_H
#define VMCS_H

#include "common.h"
#include "vmx.h"

NTSTATUS
SetupVmcs(
        _In_ PVIRTUAL_MACHINE_STATE GuestState,
        _In_ PVOID StackPointer
);

UINT32
VmcsReadInstructionErrorCode();

UINT32
VmcsReadInstructionLength();

UINT64
VmcsReadExitInstructionRip();

VOID
VmcsWriteGuestRip(
        _In_ UINT64 NewValue
);

UINT32
VmcsReadExitReason();

#endif