#include "ept.h"

NTSTATUS
hvdbgInitiateEpt(
	_Out_ PEPTP* EptBase
)
{
	PEPTP eptp = NULL;
	PEPT_PML4E pml4e = NULL;
	PEPT_PDPTE pdpte = NULL;
	PEPT_PDE pde = NULL;
	PEPT_PTE pte = NULL;

	if (!EptBase)
		return STATUS_INVALID_PARAMETER;

	*EptBase = NULL;
}


