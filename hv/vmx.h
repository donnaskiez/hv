#ifndef VMX_H
#define VMX_H

#include "vmx.h"
#include "driver.h"
#include "ia32.h"

typedef struct _DPC_CALL_CONTEXT
{
        EPT_POINTER* eptp;
        PVOID        guest_stack;
        NTSTATUS*    status;
        UINT32       status_count;

} DPC_CALL_CONTEXT, *PDPC_CALL_CONTEXT;

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

/*
 * Stores information related to exiting vmx operation
 */
typedef struct _EXIT_STATE
{
        UINT64  guest_rip;
        UINT64  guest_rsp;
        BOOLEAN exit_vmx;

} EXIT_STATE, *PEXIT_STATE;

typedef struct _VIRTUAL_MACHINE_STATE
{
        UINT64     vmxon_region_pa;
        UINT64     vmxon_region_va;
        UINT64     vmcs_region_pa;
        UINT64     vmcs_region_va;
        UINT64     eptp_va;
        UINT64     vmm_stack_va;
        UINT64     msr_bitmap_va;
        UINT64     msr_bitmap_pa;
        VMM_CACHE  cache;
        EXIT_STATE exit_state;

} VIRTUAL_MACHINE_STATE, *PVIRTUAL_MACHINE_STATE;

extern PVIRTUAL_MACHINE_STATE vmm_state;

typedef struct _DRIVER_STATE
{
        PVOID power_callback;
        PCALLBACK_OBJECT power_callback_object;

}DRIVER_STATE, *PDRIVER_STATE;

VOID
InitialiseVmxOperation(_In_ PKDPC*    Dpc,
            _In_opt_ PVOID DeferredContext,
            _In_opt_ PVOID SystemArgument1,
            _In_opt_ PVOID SystemArgument2);

NTSTATUS
BeginVmxOperation(_In_ PDPC_CALL_CONTEXT Context);

NTSTATUS
BroadcastVmxTermination();

VOID
VirtualizeCore(_In_ PDPC_CALL_CONTEXT Context, _In_ PVOID StackPointer);

NTSTATUS
SetupVmxOperation();

NTSTATUS
InitialisePowerCallback();

NTSTATUS
AllocateDriverState();

#endif