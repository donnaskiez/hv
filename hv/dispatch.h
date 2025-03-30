#ifndef EXIT_H
#define EXIT_H

#include "common.h"

#include "vmx.h"

BOOLEAN
HvDispHandleVmExit(_In_ PGUEST_CONTEXT GuestState);

VOID
HvDispDebugLoadRootRegState();

VOID
HvDispDebugStoreRootRegState();

VOID
__write_vapic_32(
    _In_ UINT64 VirtualApicPage,
    _In_ UINT32 Register,
    _In_ UINT32 Value);

VOID
__write_vapic_64(
    _In_ UINT64 VirtualApicPage,
    _In_ UINT32 Register,
    _In_ UINT64 Value);

UINT32
__read_vapic_32(_In_ UINT64 VirtualApicPage, _In_ UINT32 Register);

UINT64
__read_vapic_64(_In_ UINT64 VirtualApicPage, _In_ UINT32 Register);

#endif