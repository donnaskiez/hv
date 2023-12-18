#ifndef ARCH_H
#define ARCH_H

#include "common.h"
#include "vmx.h"

EXTERN
VOID
VmxRestoreState();

EXTERN UINT64 INLINE
SaveStateAndVirtualizeCore(_In_ PIPI_CALL_CONTEXT Context);

EXTERN
VOID
VmexitHandler();

EXTERN
ULONG64
INLINE
__readgdtbase();

EXTERN
ULONG64
INLINE
__readidtbase();

EXTERN
VOID INLINE
__vmx_enable();

EXTERN
VOID INLINE
__vmx_terminate();

EXTERN
UCHAR
INLINE
__vmx_invept(_In_ UINT32 Type, _In_ PVOID Descriptor);

EXTERN
ULONG64
__readmsr(_In_ UINT32 Msr);

EXTERN
VOID
__writemsr(_In_ UINT32 Register, _In_ UINT64 Value);

EXTERN
VOID
__writecr0(_In_ UINT64 Value);

EXTERN VOID
__writecr4(_In_ UINT64 Value);

EXTERN VOID
__lgdt(_In_ PVOID Value);

EXTERN NTSTATUS INLINE
__vmx_vmcall(UINT64 VmcallNumber,
             UINT64 OptionalParam1,
             UINT64 OptionalParam2,
             UINT64 OptionalParam3);

#endif