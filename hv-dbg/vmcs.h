#ifndef VMCS_H
#define VMCS_H

#include "common.h"
#include "vmx.h"

NTSTATUS
SetupVmcs(_In_ PVIRTUAL_MACHINE_STATE GuestState, _In_ PVOID StackPointer);

UINT32
VmcsReadInstructionErrorCode();

UINT32
VmcsReadInstructionLength();

UINT64
VmcsReadGuestRip();

VOID
VmcsWriteGuestRip(_In_ UINT64 NewValue);

UINT32
VmcsReadExitReason();

VOID
VmcsWriteGuestCr0(_In_ UINT64 NewValue);

VOID
VmcsWriteGuestCr0ReadShadow(_In_ UINT64 NewValue);

VOID
VmcsWriteGuestCr3(_In_ UINT64 NewValue);

VOID
VmcsWriteGuestCr4(_In_ UINT64 NewValue);

VOID
VmcsWriteGuestCr4ReadShadow(_In_ UINT64 NewValue);

UINT64
VmcsReadGuestRsp();

UINT32
VmcsReadExitQualification();

UINT64
VmcsReadGuestCr0();

UINT64
VmcsReadGuestCr3();

UINT64
VmcsReadGuestCr4();

UINT64
VmcsReadGuestFsBase();

UINT64
VmcsReadGuestGsBase();

UINT64
VmcsReadGuestGdtrBase();

UINT32
VmcsReadGuestGdtrLimit();

UINT64
VmcsReadGuestIdtrBase();

UINT32
VmcsReadGuestIdtrLimit();

UINT32
VmcsReadExitInterruptionInfo();

UINT32
VmcsWriteEntryInterruptionInfo(_In_ UINT32 Value);

UINT32
VmcsWriteEntryInstructionLength(_In_ UINT32 Value);

#endif