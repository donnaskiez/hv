#ifndef VMX_H
#define VMX_H

#include "driver.h"
#include "ia32.h"
#include "lock.h"

typedef struct _DPC_CALL_CONTEXT {
        EPT_POINTER* eptp;
        PVOID        guest_stack;
        NTSTATUS*    status;
        UINT32       status_count;

} DPC_CALL_CONTEXT, *PDPC_CALL_CONTEXT;

typedef struct _CPUID_CACHE {
        INT32            value[4];
        volatile BOOLEAN active;

} CPUID_CACHE, *PCPUID_CACHE;

/*
 * This structure will act as the per-cpu cache for commonly accessed items
 * such as CPUID result as this won't change.
 */
typedef struct _VMM_CACHE {
        CPUID_CACHE cpuid;

} VMM_CACHE, *PVMM_CACHE;

/*
 * Stores information related to exiting vmx operation
 */
typedef struct _EXIT_STATE {
        UINT64  guest_rip;
        UINT64  guest_rsp;
        BOOLEAN exit_vmx;

} EXIT_STATE, *PEXIT_STATE;

#define VMX_VCPU_STATE_OFF        0
#define VMX_VCPU_STATE_RUNNING    1
#define VMX_VCPU_STATE_TERMINATED 2

typedef enum _VCPU_STATE { off, running, terminated } VCPU_STATE;

#define VMX_LOG_BUFFER_SIZE          0x100000
#define VMX_INIDIVIDUAL_LOG_MAX_SIZE 0x100
#define VMX_MAX_LOG_ENTRIES_COUNT    VMX_LOG_BUFFER_SIZE / VMX_INIDIVIDUAL_LOG_MAX_SIZE
#define VMX_LOG_BUFFER_POOL_TAG      'rgol'

typedef struct _VCPU_LOG_STATE {
        volatile HIGH_IRQL_LOCK lock;
        KDPC                    dpc;
        PVOID                   log_buffer;
        volatile UINT32         current_log_count;

} VCPU_LOG_STATE, *PVCPU_LOG_STATE;

typedef struct _VIRTUAL_MACHINE_STATE {
        VCPU_STATE     state;
        VMM_CACHE      cache;
        EXIT_STATE     exit_state;
        PGUEST_CONTEXT guest_context;
        UINT64         vmxon_region_pa;
        UINT64         vmxon_region_va;
        UINT64         vmcs_region_pa;
        UINT64         vmcs_region_va;
        UINT64         eptp_va;
        UINT64         vmm_stack_va;
        UINT64         msr_bitmap_va;
        UINT64         msr_bitmap_pa;
#ifdef DEBUG
        VCPU_LOG_STATE log_state;
#endif

} VIRTUAL_MACHINE_STATE, *PVIRTUAL_MACHINE_STATE;

extern PVIRTUAL_MACHINE_STATE vmm_state;

typedef struct _DRIVER_STATE {
        PVOID            power_callback;
        PCALLBACK_OBJECT power_callback_object;

} DRIVER_STATE, *PDRIVER_STATE;

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