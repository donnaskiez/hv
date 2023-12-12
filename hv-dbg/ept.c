#include "ept.h"

#include "vmx.h"

#define NUM_PAGES 100

NTSTATUS
InitializeEptp(_Out_ EPT_POINTER ** EptPointer)
{
        EPT_PML4E *   pml4          = NULL;
        EPT_PDPTE *   pdpt          = NULL;
        EPT_PDE *     pd            = NULL;
        EPT_PTE *     pt            = NULL;
        EPT_POINTER * ept           = NULL;
        UINT64        guest_virtual = NULL;

        *EptPointer = NULL;

        ept = ExAllocatePool2(POOL_FLAG_NON_PAGED, PAGE_SIZE, POOLTAG);

        if (!ept)
                return STATUS_MEMORY_NOT_ALLOCATED;

        /*
         * For whatever reason we need to zero out the allocations even though
         * ExAllocatePool2 is meant to zero them out for us. If we don't zero
         * them out it produces a page fault
         */
        RtlZeroMemory(ept, PAGE_SIZE);

        pml4 = ExAllocatePool2(POOL_FLAG_NON_PAGED, PAGE_SIZE, POOLTAG);

        if (!pml4)
        {
                ExFreePoolWithTag(ept, POOLTAG);
                return STATUS_MEMORY_NOT_ALLOCATED;
        }

        RtlZeroMemory(pml4, PAGE_SIZE);

        pdpt = ExAllocatePool2(POOL_FLAG_NON_PAGED, PAGE_SIZE, POOLTAG);

        if (!pdpt)
        {
                ExFreePoolWithTag(pml4, POOLTAG);
                ExFreePoolWithTag(ept, POOLTAG);
                return STATUS_MEMORY_NOT_ALLOCATED;
        }

        RtlZeroMemory(pdpt, PAGE_SIZE);

        pd = ExAllocatePool2(POOL_FLAG_NON_PAGED, PAGE_SIZE, POOLTAG);

        if (!pd)
        {
                ExFreePoolWithTag(pdpt, POOLTAG);
                ExFreePoolWithTag(pml4, POOLTAG);
                ExFreePoolWithTag(ept, POOLTAG);
                return STATUS_MEMORY_NOT_ALLOCATED;
        }

        RtlZeroMemory(pd, PAGE_SIZE);

        pt = ExAllocatePool2(POOL_FLAG_NON_PAGED, PAGE_SIZE, POOLTAG);

        if (!pt)
        {
                ExFreePoolWithTag(pd, POOLTAG);
                ExFreePoolWithTag(pdpt, POOLTAG);
                ExFreePoolWithTag(pml4, POOLTAG);
                ExFreePoolWithTag(ept, POOLTAG);
                return STATUS_MEMORY_NOT_ALLOCATED;
        }

        RtlZeroMemory(pt, PAGE_SIZE);

        guest_virtual = ExAllocatePool2(POOL_FLAG_NON_PAGED,
                                        NUM_PAGES * PAGE_SIZE,
                                        POOLTAG);

        if (!guest_virtual)
        {
                ExFreePoolWithTag(pt, POOLTAG);
                ExFreePoolWithTag(pd, POOLTAG);
                ExFreePoolWithTag(pdpt, POOLTAG);
                ExFreePoolWithTag(pml4, POOLTAG);
                ExFreePoolWithTag(ept, POOLTAG);
                return STATUS_MEMORY_NOT_ALLOCATED;
        }

        RtlZeroMemory(guest_virtual, PAGE_SIZE);

        for (SIZE_T index = 0; index < NUM_PAGES; index++)
        {
                pt[index].Fields.Accessed        = 0;
                pt[index].Fields.Dirty           = 0;
                pt[index].Fields.MemoryType      = 6;
                pt[index].Fields.ExecuteAccess   = 1;
                pt[index].Fields.UserModeExecute = 0;
                pt[index].Fields.IgnorePat       = 0;
                pt[index].Fields.PageFrameNumber =
                    MmGetPhysicalAddress(guest_virtual + (index * PAGE_SIZE))
                        .QuadPart /
                    PAGE_SIZE;
                pt[index].Fields.ReadAccess  = 1;
                pt[index].Fields.SuppressVe  = 0;
                pt[index].Fields.WriteAccess = 1;
        }

        pd->Fields.Accessed        = 0;
        pd->Fields.ExecuteAccess   = 1;
        pd->Fields.UserModeExecute = 0;
        pd->Fields.Reserved1       = 0;
        pd->Fields.Reserved2       = 0;
        pd->Fields.Reserved3       = 0;
        pd->Fields.PageFrameNumber =
            MmGetPhysicalAddress(pt).QuadPart / PAGE_SIZE;
        pd->Fields.ReadAccess  = 1;
        pd->Fields.Reserved1   = 0;
        pd->Fields.Reserved2   = 0;
        pd->Fields.WriteAccess = 1;

        pdpt->Fields.Accessed        = 0;
        pdpt->Fields.ExecuteAccess   = 1;
        pdpt->Fields.UserModeExecute = 0;
        pdpt->Fields.Reserved1       = 0;
        pdpt->Fields.Reserved2       = 0;
        pdpt->Fields.Reserved3       = 0;
        pdpt->Fields.PageFrameNumber =
            MmGetPhysicalAddress(pd).QuadPart / PAGE_SIZE;
        pdpt->Fields.ReadAccess  = 1;
        pdpt->Fields.Reserved1   = 0;
        pdpt->Fields.Reserved2   = 0;
        pdpt->Fields.WriteAccess = 1;

        pml4->Fields.Accessed        = 0;
        pml4->Fields.ExecuteAccess   = 1;
        pml4->Fields.UserModeExecute = 0;
        pml4->Fields.Reserved1       = 0;
        pml4->Fields.Reserved2       = 0;
        pml4->Fields.Reserved3       = 0;
        pml4->Fields.PageFrameNumber =
            MmGetPhysicalAddress(pdpt).QuadPart / PAGE_SIZE;
        pml4->Fields.ReadAccess  = 1;
        pml4->Fields.Reserved1   = 0;
        pml4->Fields.Reserved2   = 0;
        pml4->Fields.WriteAccess = 1;

        ept->Fields.EnableAccessAndDirtyFlags = 1;
        ept->Fields.MemoryType                = 6;
        ept->Fields.PageWalkLength            = 3;
        ept->Fields.PageFrameNumber =
            MmGetPhysicalAddress(pml4).QuadPart / PAGE_SIZE;
        ept->Fields.Reserved1 = 0;
        ept->Fields.Reserved2 = 0;

        *EptPointer = ept;

        return STATUS_SUCCESS;
}