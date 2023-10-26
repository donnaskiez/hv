#include "ept.h"

#define POOL_TAG_EPT 'eptp'

UINT64 guest_virtual_memory_address = 0;

NTSTATUS
hvdbgInitiateEpt(
	_Out_ PEPTP* EptPointer
)
{
	PEPTP eptp = NULL;
	PEPT_PML4E pml4e = NULL;
	PEPT_PDPTE pdpte = NULL;
	PEPT_PDE pde = NULL;
	PEPT_PTE pte = NULL;
	UINT64 guest_memory = 0;

	if (!EptPointer)
		return STATUS_INVALID_PARAMETER;

	*EptPointer = NULL;

	eptp = ExAllocatePool2(POOL_FLAG_NON_PAGED, PAGE_SIZE, POOL_TAG_EPT);

	if (!eptp)
		return STATUS_MEMORY_NOT_ALLOCATED;

	pml4e  = ExAllocatePool2(POOL_FLAG_NON_PAGED, PAGE_SIZE, POOL_TAG_EPT);

	if (!pml4e)
		goto fail;

	pdpte = ExAllocatePool2(POOL_FLAG_NON_PAGED, PAGE_SIZE, POOL_TAG_EPT);

	if (!pdpte)
		goto fail;

	pde = ExAllocatePool2(POOL_FLAG_NON_PAGED, PAGE_SIZE, POOL_TAG_EPT);

	if (!pde)
		goto fail;

	pte = ExAllocatePool2(POOL_FLAG_NON_PAGED, PAGE_SIZE, POOL_TAG_EPT);

	if (!pte)
		goto fail;

	guest_memory = ExAllocatePool2(POOL_FLAG_NON_PAGED, 100 * PAGE_SIZE, POOL_TAG_EPT);

	if (!guest_memory)
		goto fail;

	guest_virtual_memory_address = guest_memory;

	for (INT index = 0; index < 100; index++)
	{
		pte[index].Fields.AccessedFlag = 0;
		pte[index].Fields.DirtyFlag = 0;
		pte[index].Fields.EPTMemoryType = 6;
		pte[index].Fields.Execute = 1;
		pte[index].Fields.ExecuteForUserMode = 0;
		pte[index].Fields.IgnorePAT = 0;
		pte[index].Fields.PhysicalAddress = MmGetPhysicalAddress(guest_memory + (index * PAGE_SIZE)).QuadPart / PAGE_SIZE;
		pte[index].Fields.Read = 1;
		pte[index].Fields.SuppressVE = 0;
		pte[index].Fields.Write = 1;
	}

	pde->Fields.Accessed = 0;
	pde->Fields.Execute = 1;
	pde->Fields.ExecuteForUserMode = 0;
	pde->Fields.Ignored1 = 0;
	pde->Fields.Ignored2 = 0;
	pde->Fields.Ignored3 = 0;
	pde->Fields.PhysicalAddress = MmGetPhysicalAddress(pte).QuadPart / PAGE_SIZE;
	pde->Fields.Read = 1;
	pde->Fields.Reserved1 = 0;
	pde->Fields.Reserved2 = 0;
	pde->Fields.Write = 1;

	pdpte->Fields.Accessed = 0;
	pdpte->Fields.Execute = 1;
	pdpte->Fields.ExecuteForUserMode = 0;
	pdpte->Fields.Ignored1 = 0;
	pdpte->Fields.Ignored2 = 0;
	pdpte->Fields.Ignored3 = 0;
	pdpte->Fields.PhysicalAddress = MmGetPhysicalAddress(pde).QuadPart / PAGE_SIZE;
	pdpte->Fields.Read = 1;
	pdpte->Fields.Reserved1 = 0;
	pdpte->Fields.Reserved2 = 0;
	pdpte->Fields.Write = 1;

	pml4e->Fields.Accessed = 0;
	pml4e->Fields.Execute = 1;
	pml4e->Fields.ExecuteForUserMode = 0;
	pml4e->Fields.Ignored1 = 0;
	pml4e->Fields.Ignored2 = 0;
	pml4e->Fields.Ignored3 = 0;
	pml4e->Fields.PhysicalAddress = MmGetPhysicalAddress(pdpte).QuadPart / PAGE_SIZE;
	pml4e->Fields.Read = 1;
	pml4e->Fields.Reserved1 = 0;
	pml4e->Fields.Reserved2 = 0;
	pml4e->Fields.Write = 1;

	eptp->Fields.DirtyAndAceessEnabled = 1;
	eptp->Fields.MemoryType = 6; // 6 = Write-back (WB)
	eptp->Fields.PageWalkLength = 3; // 4 (tables walked) - 1 = 3
	eptp->Fields.PML4Address = MmGetPhysicalAddress(pml4e).QuadPart / PAGE_SIZE;
	eptp->Fields.Reserved1 = 0;
	eptp->Fields.Reserved2 = 0;

	*EptPointer = eptp;

	return STATUS_SUCCESS;

fail:
	if (guest_memory)
		ExFreePoolWithTag(guest_memory, POOL_TAG_EPT);
	if (eptp)
		ExFreePoolWithTag(eptp, POOL_TAG_EPT);
	if (pml4e)
		ExFreePoolWithTag(pml4e, POOL_TAG_EPT);
	if (pdpte)
		ExFreePoolWithTag(pdpte, POOL_TAG_EPT);
	if (pde)
		ExFreePoolWithTag(pde, POOL_TAG_EPT);
	if (pte)
		ExFreePoolWithTag(pte, POOL_TAG_EPT);

	return STATUS_MEMORY_NOT_ALLOCATED;
}


