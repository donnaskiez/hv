#ifndef VMX_H
#define VMX_H

#include "driver.h"
#include "ia32.h"

typedef struct _DPC_CALL_CONTEXT {
    EPT_POINTER* eptp;
    PVOID guest_stack;
    NTSTATUS* status;
    UINT32 status_count;

} DPC_CALL_CONTEXT, *PDPC_CALL_CONTEXT;

typedef struct _CPUID_CACHE {
    INT32 value[4];
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
    UINT64 guest_rip;
    UINT64 guest_rsp;
    UINT64 guest_debug_ctl;
    BOOLEAN exit_vmx;

} EXIT_STATE, *PEXIT_STATE;

#define VMX_VCPU_STATE_OFF         0
#define VMX_VCPU_STATE_RUNNING     1
#define VMX_VCPU_STATE_TERMINATING 2
#define VMX_VCPU_STATE_TERMINATED  3

typedef enum _VCPU_STATE { off, running, terminated } VCPU_STATE;

#define VMX_LOG_BUFFER_SIZE          64000
#define VMX_INIDIVIDUAL_LOG_MAX_SIZE 128
#define VMX_MAX_LOG_ENTRIES_COUNT \
    (VMX_LOG_BUFFER_SIZE / VMX_INIDIVIDUAL_LOG_MAX_SIZE)
#define VMX_LOG_BUFFER_POOL_TAG 'rgol'

#define VMX_APIC_TPR_THRESHOLD 0

typedef struct _LOG_ENTRY {
    UINT64 timestamp;
    CHAR message[VMX_INIDIVIDUAL_LOG_MAX_SIZE];
} LOG_ENTRY, *PLOG_ENTRY;

typedef struct _VCPU_LOG_STATE {
    volatile UINT32 head;
    volatile UINT32 tail;
    volatile UINT32 flushing;
    volatile UINT64 log_count;
    volatile UINT64 discard_count;
    volatile UINT64 flush_miss_count;
    KDPC dpc;
    LOG_ENTRY logs[VMX_MAX_LOG_ENTRIES_COUNT];
} VCPU_LOG_STATE, *PVCPU_LOG_STATE;

typedef struct _GUEST_CONTEXT {
    UINT64 dr7;
    UINT64 dr6;
    UINT64 dr3;
    UINT64 dr2;
    UINT64 dr1;
    UINT64 dr0;
    // M128A  Xmm0;
    // M128A  Xmm1;
    // M128A  Xmm2;
    // M128A  Xmm3;
    // M128A  Xmm4;
    // M128A  Xmm5;
    // M128A  Xmm6;
    // M128A  Xmm7;
    // M128A  Xmm8;
    // M128A  Xmm9;
    // M128A  Xmm10;
    // M128A  Xmm11;
    // M128A  Xmm12;
    // M128A  Xmm13;
    // M128A  Xmm14;
    // M128A  Xmm15;
    UINT64 rax;
    UINT64 rcx;
    UINT64 rdx;
    UINT64 rbx;
    UINT64 rsp;
    UINT64 rbp;
    UINT64 rsi;
    UINT64 rdi;
    UINT64 r8;
    UINT64 r9;
    UINT64 r10;
    UINT64 r11;
    UINT64 r12;
    UINT64 r13;
    UINT64 r14;
    UINT64 r15;
    UINT64 rflags;

} GUEST_CONTEXT, *PGUEST_CONTEXT;

typedef struct _MSR_BITMAP {
    UINT8 msr_low_read[1024];
    UINT8 msr_high_read[1024];
    UINT8 msr_low_write[1024];
    UINT8 msr_high_write[1024];
} MSR_BITMAP, *PMSR_BITMAP;

typedef struct _HOST_DEBUG_STATE {
    UINT64 dr0;
    UINT64 dr1;
    UINT64 dr2;
    UINT64 dr3;
    UINT64 dr6;
    UINT64 dr7;
    UINT64 debug_ctl;

} HOST_DEBUG_STATE, *PHOST_DEBUG_STATE;

typedef struct _VCPU_STATS {
    UINT64 exit_count;

    struct {
        UINT64 cpuid;
        UINT64 invd;
        UINT64 vmcall;
        UINT64 mov_cr;
        UINT64 wbinvd;
        UINT64 tpr_threshold;
        UINT64 exception_or_nmi;
        UINT64 trap_flags;
        UINT64 wrmsr;
        UINT64 rdmsr;
        UINT64 mov_dr;
        UINT64 virtualised_eoi;
        UINT64 preemption_timer;
    } reasons;

} VCPU_STATS, *PVCPU_STATS;

#define HV_VCPU_PENDING_PROC_CTLS_UPDATE        (1ul << 0)
#define HV_VCPU_PENDING_PROC_CTLS2_UPDATE       (1ul << 1)
#define HV_VCPU_PENDING_PIN_CTLS_UPDATE         (1ul << 2)
#define HV_VCPU_PENDING_EXIT_CTLS_UPDATE        (1ul << 3)
#define HV_VCPU_PENDING_ENTRY_CTLS_UPDATE       (1ul << 4)
#define HV_VCPU_PENDING_EXCEPTION_BITMAP_UPDATE (1ul << 5)
#define HV_VCPU_PENDING_MSR_BITMAP_UPDATE       (1ul << 6)

#define HV_VCPU_IS_PENDING_VMCS_UPDATE(vcpu) ((vcpu)->pend_updates != 0)

typedef struct _VCPU {
    VCPU_STATE state;
    VMM_CACHE cache;
    EXIT_STATE exit_state;
    PGUEST_CONTEXT guest_context;
    UINT64 vmxon_region_pa;
    UINT64 vmxon_region_va;
    UINT64 vmcs_region_pa;
    UINT64 vmcs_region_va;
    UINT64 eptp_va;
    UINT64 vmm_stack_va;
    PMSR_BITMAP msr_bitmap_va;
    PMSR_BITMAP msr_bitmap_pa;
    PUINT8 virtual_apic_va;
    PUINT8 virtual_apic_pa;
    UINT32 exception_bitmap;
    UINT32 exception_bitmap_mask;
    HOST_DEBUG_STATE debug_state;
    IA32_VMX_PROCBASED_CTLS_REGISTER proc_ctls;
    IA32_VMX_PROCBASED_CTLS2_REGISTER proc_ctls2;
    IA32_VMX_PINBASED_CTLS_REGISTER pin_ctls;
    IA32_VMX_EXIT_CTLS_REGISTER exit_ctls;
    IA32_VMX_ENTRY_CTLS_REGISTER entry_ctls;
    UINT32 pend_updates;
    VCPU_STATS stats;
#ifdef DEBUG
    UINT32 preemption_time;
    VCPU_LOG_STATE log_state;
#endif

} VCPU, *PVCPU;

#define SET_FLAG_U32(n) (1U << (n))

extern PVCPU vmm_state;

typedef struct _DRIVER_STATE {
    PVOID power_callback;
    PCALLBACK_OBJECT power_callback_object;
    // EPT_CONFIGURATION ept_configuration;

} DRIVER_STATE, *PDRIVER_STATE;

typedef union {
    struct {
        UINT32 TaskPriorityRegisterThreshold : 4;
        UINT32 VirtualTaskPriorityRegister : 4;
        UINT32 Unused2 : 24;
    };
    UINT32 AsUInt;
} VTPR, *PVTPR;

VOID
HvVmxDpcInitOperation(
    _In_ PKDPC* Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2);

NTSTATUS
HvVmxStartOperation(_In_ PDPC_CALL_CONTEXT Context);

NTSTATUS
HvVmxBroadcastTermination();

VOID
HvVmxVirtualiseCore(_In_ PDPC_CALL_CONTEXT Context, _In_ PVOID StackPointer);

NTSTATUS
HvVmxInitialiseOperation();

NTSTATUS
HvVmxPowerCbInit();

NTSTATUS
HvVmxAllocateDriverState();

VOID
HvVmxFreeDriverState();

VOID
HvVmxPowerCbUnregister();

VOID
HvVmxFreeVcpuArray();

#endif