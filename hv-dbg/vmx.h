#ifndef VMX_H
#define VMX_H

#include "common.h"
#include "vmx.h"
#include "driver.h"

typedef struct _IPI_CALL_CONTEXT
{
	PVOID eptp;
	PVOID guest_stack;

}IPI_CALL_CONTEXT, * PIPI_CALL_CONTEXT;

typedef struct _VIRTUAL_MACHINE_STATE
{
	UINT64 vmxon_region_pa;
	UINT64 vmxon_region_va;
	UINT64 vmcs_region_pa;
	UINT64 vmcs_region_va;
	UINT64 eptp;
	UINT64 vmm_stack;
	UINT64 msr_bitmap_va;
	UINT64 msr_bitmap_pa;

} VIRTUAL_MACHINE_STATE, * PVIRTUAL_MACHINE_STATE;

UINT64 stack_pointer_to_return;
UINT64 base_pointer_to_return;

VOID
InitiateVmx(
	_In_ PIPI_CALL_CONTEXT Context
);

BOOLEAN
BroadcastVmxInitiation(
	_In_ PIPI_CALL_CONTEXT Context
);

BOOLEAN
BroadcastVmxTermination();

VOID
VirtualizeCore(
	_In_ PIPI_CALL_CONTEXT Context,
	_In_ PVOID StackPointer
);

extern 
VOID
VmexitHandler();

extern 
ULONG64 
inline 
__readgdtbase();

extern 
ULONG64 
inline 
__readidtbase();

extern 
void 
inline 
__vmx_enable();

extern
void 
inline 
__vmx_terminate();

extern 
unsigned char 
inline 
__vmx_invept(
	_In_ ULONG Type, 
	_In_ PVOID Descriptor
);

ULONG64
__readmsr(ULONG32 reg);

void
__writemsr(ULONG32 reg, ULONG64 MsrValue);

extern void VmxRestoreState();

extern UINT64 inline SaveStateAndVirtualizeCore(_In_ PIPI_CALL_CONTEXT Context);

#endif