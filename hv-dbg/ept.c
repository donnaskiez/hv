#include "common.h"
#include "vmx.h"
#include "ept.h"

#define NUM_PAGES 100

NTSTATUS
InitializeEptp(
        _Out_ PEPTP* EptPointer
)
{
        PEPT_PML4E pml4 = NULL;
        PEPT_PDPTE pdpt = NULL;
        PEPT_PDE pd = NULL;
        PEPT_PTE pt = NULL;
        PEPTP ept_pointer = NULL;
        UINT64 guest_virtual = NULL;

        *EptPointer = NULL;

        ept_pointer = ExAllocatePool2(POOL_FLAG_NON_PAGED, PAGE_SIZE, POOLTAG);

        if (!ept_pointer)
                return STATUS_MEMORY_NOT_ALLOCATED;

        /*
        * For whatever reason we need to zero out the allocations even though ExAllocatePool2
        * is meant to zero them out for us. If we don't zero them out it produces a page fault
        */
        RtlZeroMemory(ept_pointer, PAGE_SIZE);

        pml4 = ExAllocatePool2(POOL_FLAG_NON_PAGED, PAGE_SIZE, POOLTAG);

        if (!pml4)
        {
                ExFreePoolWithTag(ept_pointer, POOLTAG);
                return STATUS_MEMORY_NOT_ALLOCATED;
        }

        RtlZeroMemory(pml4, PAGE_SIZE);

        pdpt = ExAllocatePool2(POOL_FLAG_NON_PAGED, PAGE_SIZE, POOLTAG);

        if (!pdpt)
        {
                ExFreePoolWithTag(pml4, POOLTAG);
                ExFreePoolWithTag(ept_pointer, POOLTAG);
                return STATUS_MEMORY_NOT_ALLOCATED;
        }

        RtlZeroMemory(pdpt, PAGE_SIZE);

        pd = ExAllocatePool2(POOL_FLAG_NON_PAGED, PAGE_SIZE, POOLTAG);

        if (!pd)
        {
                ExFreePoolWithTag(pdpt, POOLTAG);
                ExFreePoolWithTag(pml4, POOLTAG);
                ExFreePoolWithTag(ept_pointer, POOLTAG);
                return STATUS_MEMORY_NOT_ALLOCATED;
        }

        RtlZeroMemory(pd, PAGE_SIZE);

        pt = ExAllocatePool2(POOL_FLAG_NON_PAGED, PAGE_SIZE, POOLTAG);

        if (!pt)
        {
                ExFreePoolWithTag(pd, POOLTAG);
                ExFreePoolWithTag(pdpt, POOLTAG);
                ExFreePoolWithTag(pml4, POOLTAG);
                ExFreePoolWithTag(ept_pointer, POOLTAG);
                return STATUS_MEMORY_NOT_ALLOCATED;
        }

        RtlZeroMemory(pt, PAGE_SIZE);

        guest_virtual = ExAllocatePool2(POOL_FLAG_NON_PAGED, NUM_PAGES * PAGE_SIZE, POOLTAG);

        if (!guest_virtual)
        {
                ExFreePoolWithTag(pt, POOLTAG);
                ExFreePoolWithTag(pd, POOLTAG);
                ExFreePoolWithTag(pdpt, POOLTAG);
                ExFreePoolWithTag(pml4, POOLTAG);
                ExFreePoolWithTag(ept_pointer, POOLTAG);
                return STATUS_MEMORY_NOT_ALLOCATED;
        }

        RtlZeroMemory(guest_virtual, PAGE_SIZE);

        for (SIZE_T index = 0; index < NUM_PAGES; index++)
        {
                pt[index].Fields.AccessedFlag = 0;
                pt[index].Fields.DirtyFlag = 0;
                pt[index].Fields.EPTMemoryType = 6;
                pt[index].Fields.Execute = 1;
                pt[index].Fields.ExecuteForUserMode = 0;
                pt[index].Fields.IgnorePAT = 0;
                pt[index].Fields.PhysicalAddress = MmGetPhysicalAddress(guest_virtual + (index * PAGE_SIZE)).QuadPart / PAGE_SIZE;
                pt[index].Fields.Read = 1;
                pt[index].Fields.SuppressVE = 0;
                pt[index].Fields.Write = 1;
        }

        pd->Fields.Accessed = 0;
        pd->Fields.Execute = 1;
        pd->Fields.ExecuteForUserMode = 0;
        pd->Fields.Ignored1 = 0;
        pd->Fields.Ignored2 = 0;
        pd->Fields.Ignored3 = 0;
        pd->Fields.PhysicalAddress = MmGetPhysicalAddress(pt).QuadPart / PAGE_SIZE;
        pd->Fields.Read = 1;
        pd->Fields.Reserved1 = 0;
        pd->Fields.Reserved2 = 0;
        pd->Fields.Write = 1;

        pdpt->Fields.Accessed = 0;
        pdpt->Fields.Execute = 1;
        pdpt->Fields.ExecuteForUserMode = 0;
        pdpt->Fields.Ignored1 = 0;
        pdpt->Fields.Ignored2 = 0;
        pdpt->Fields.Ignored3 = 0;
        pdpt->Fields.PhysicalAddress = MmGetPhysicalAddress(pd).QuadPart / PAGE_SIZE;
        pdpt->Fields.Read = 1;
        pdpt->Fields.Reserved1 = 0;
        pdpt->Fields.Reserved2 = 0;
        pdpt->Fields.Write = 1;

        pml4->Fields.Accessed = 0;
        pml4->Fields.Execute = 1;
        pml4->Fields.ExecuteForUserMode = 0;
        pml4->Fields.Ignored1 = 0;
        pml4->Fields.Ignored2 = 0;
        pml4->Fields.Ignored3 = 0;
        pml4->Fields.PhysicalAddress = MmGetPhysicalAddress(pdpt).QuadPart / PAGE_SIZE;
        pml4->Fields.Read = 1;
        pml4->Fields.Reserved1 = 0;
        pml4->Fields.Reserved2 = 0;
        pml4->Fields.Write = 1;

        ept_pointer->Fields.DirtyAndAceessEnabled = 1;
        ept_pointer->Fields.MemoryType = 6;
        ept_pointer->Fields.PageWalkLength = 3;
        ept_pointer->Fields.PML4Address = MmGetPhysicalAddress(pml4).QuadPart / PAGE_SIZE;
        ept_pointer->Fields.Reserved1 = 0;
        ept_pointer->Fields.Reserved2 = 0;

        *EptPointer = ept_pointer;

        return STATUS_SUCCESS;
}