#ifndef VMX_H
#define VMX_H

#include "vmx.h"
#include "driver.h"
#include "ia32.h"

typedef struct _IPI_CALL_CONTEXT
{
        EPT_POINTER* eptp;
        PVOID        guest_stack;

} IPI_CALL_CONTEXT, *PIPI_CALL_CONTEXT;

typedef struct _CPUID_CACHE
{
        INT32            value[4];
        volatile BOOLEAN active;

} CPUID_CACHE, *PCPUID_CACHE;

/*
 * This structure will act as the per-cpu cache for commonly accessed items
 * such as CPUID result as this won't change.
 */
typedef struct _VMM_CACHE
{
        CPUID_CACHE cpuid;

} VMM_CACHE, *PVMM_CACHE;

typedef struct _VIRTUAL_MACHINE_STATE
{
        UINT64    vmxon_region_pa;
        UINT64    vmxon_region_va;
        UINT64    vmcs_region_pa;
        UINT64    vmcs_region_va;
        UINT64    eptp_va;
        UINT64    vmm_stack_va;
        UINT64    msr_bitmap_va;
        UINT64    msr_bitmap_pa;
        VMM_CACHE cache;

} VIRTUAL_MACHINE_STATE, *PVIRTUAL_MACHINE_STATE;

extern PVIRTUAL_MACHINE_STATE vmm_state;

NTSTATUS
InitiateVmx(_In_ PIPI_CALL_CONTEXT Context);

BOOLEAN
BroadcastVmxInitiation(_In_ PIPI_CALL_CONTEXT Context);

BOOLEAN
BroadcastVmxTermination();

VOID
VirtualizeCore(_In_ PIPI_CALL_CONTEXT Context, _In_ PVOID StackPointer);

#endif