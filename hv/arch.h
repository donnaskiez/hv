#ifndef ARCH_H
#define ARCH_H

#include "common.h"
#include "vmx.h"

EXTERN
VOID
VmxRestoreState();

EXTERN UINT64 INLINE
SaveStateAndVirtualizeCore(_In_ PDPC_CALL_CONTEXT Context);

EXTERN
VOID
VmexitHandler();

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
__vmx_vmcall(_In_ UINT64 VmcallNumber,
             _In_ UINT64 OptionalParam1,
             _In_ UINT64 OptionalParam2,
             _In_ UINT64 OptionalParam3);

EXTERN UINT64
__lar(_In_ UINT64 Selector);

EXTERN VOID
__sgdt(_In_ SEGMENT_DESCRIPTOR_REGISTER_64* Gdtr);

EXTERN UINT16 __readcs(VOID);

EXTERN UINT16 __readds(VOID);

EXTERN UINT16 __reades(VOID);

EXTERN UINT16 __readss(VOID);

EXTERN UINT16 __readfs(VOID);

EXTERN UINT16 __readgs(VOID);

EXTERN UINT16 __readldtr(VOID);

EXTERN UINT16 __readtr(VOID);

EXTERN UINT64 __readrflags(VOID);

EXTERN UINT16
__sldt();

#endif