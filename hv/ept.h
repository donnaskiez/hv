#ifndef EPT_H
#define EPT_H

#include <ntddk.h>

#include "ia32.h"

/*
 * Addresses used to setup extended page tables. This is simply a housekeeping
 * structure allowing us to more easily free the allocations on unload /
 * termination.
 */
typedef struct _EPT_CONFIGURATION {
        EPT_PML4E*   pml4;
        EPT_PDPTE*   pdpt;
        EPT_PDE*     pd;
        EPT_PTE*     pt;
        EPT_POINTER* ept;
        UINT64       guest_virtual;
} EPT_CONFIGURATION, *PEPT_CONFIGURATION;

#define EPT_GUEST_PAGE_ALLOCATION_COUNT 100

NTSTATUS
InitializeEptp(_Out_ PEPT_CONFIGURATION Configuration);

VOID
FreeEptStructures(_In_ PEPT_CONFIGURATION Configuration);

#endif