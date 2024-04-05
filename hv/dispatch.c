#include "dispatch.h"

#include "vmx.h"
#include "vmcs.h"
#include <intrin.h>
#include "arch.h"
#include "log.h"

#define CPUID_HYPERVISOR_INTERFACE_VENDOR 0x40000000
#define CPUID_HYPERVISOR_INTERFACE_LOL    0x40000001

#define VMX_CPUID_FUNCTION_LOW  0x40000000
#define VMX_CPUID_FUNCTION_HIGH 0x400000FF

#define CPUID_EAX 0
#define CPUID_EBX 1
#define CPUID_ECX 2
#define CPUID_EDX 3

#define VMX_BUGCHECK_INVALID_MTF_EXIT 0x0

FORCEINLINE
STATIC
VOID
IncrementGuestRip()
{
        VmxVmWrite(VMCS_GUEST_RIP,
                   VmxVmRead(VMCS_GUEST_RIP) +
                       VmxVmRead(VMCS_VMEXIT_INSTRUCTION_LENGTH));
}

FORCEINLINE
STATIC
UINT64
RetrieveValueInContextRegister(_In_ PGUEST_CONTEXT Context,
                               _In_ UINT32         Register)
{
        switch (Register) {
        case VMX_EXIT_QUALIFICATION_GENREG_RAX: return Context->rax;
        case VMX_EXIT_QUALIFICATION_GENREG_RCX: return Context->rcx;
        case VMX_EXIT_QUALIFICATION_GENREG_RDX: return Context->rdx;
        case VMX_EXIT_QUALIFICATION_GENREG_RBX: return Context->rbx;
        case VMX_EXIT_QUALIFICATION_GENREG_RSP: return Context->rsp;
        case VMX_EXIT_QUALIFICATION_GENREG_RBP: return Context->rbp;
        case VMX_EXIT_QUALIFICATION_GENREG_RSI: return Context->rsi;
        case VMX_EXIT_QUALIFICATION_GENREG_RDI: return Context->rdi;
        case VMX_EXIT_QUALIFICATION_GENREG_R8: return Context->r8;
        case VMX_EXIT_QUALIFICATION_GENREG_R9: return Context->r9;
        case VMX_EXIT_QUALIFICATION_GENREG_R10: return Context->r10;
        case VMX_EXIT_QUALIFICATION_GENREG_R11: return Context->r11;
        case VMX_EXIT_QUALIFICATION_GENREG_R12: return Context->r12;
        case VMX_EXIT_QUALIFICATION_GENREG_R13: return Context->r13;
        case VMX_EXIT_QUALIFICATION_GENREG_R14: return Context->r14;
        case VMX_EXIT_QUALIFICATION_GENREG_R15: return Context->r15;
        default: return 0;
        }
}

FORCEINLINE
STATIC
VOID
WriteValueInContextRegister(_In_ PGUEST_CONTEXT Context,
                            _In_ UINT32         Register,
                            _In_ UINT64         Value)
{
        switch (Register) {
        case VMX_EXIT_QUALIFICATION_GENREG_RAX: Context->rax = Value; return;
        case VMX_EXIT_QUALIFICATION_GENREG_RCX: Context->rcx = Value; return;
        case VMX_EXIT_QUALIFICATION_GENREG_RDX: Context->rdx = Value; return;
        case VMX_EXIT_QUALIFICATION_GENREG_RBX: Context->rbx = Value; return;
        case VMX_EXIT_QUALIFICATION_GENREG_RSP: Context->rsp = Value; return;
        case VMX_EXIT_QUALIFICATION_GENREG_RBP: Context->rbp = Value; return;
        case VMX_EXIT_QUALIFICATION_GENREG_RSI: Context->rsi = Value; return;
        case VMX_EXIT_QUALIFICATION_GENREG_RDI: Context->rdi = Value; return;
        case VMX_EXIT_QUALIFICATION_GENREG_R8: Context->r8 = Value; return;
        case VMX_EXIT_QUALIFICATION_GENREG_R9: Context->r9 = Value; return;
        case VMX_EXIT_QUALIFICATION_GENREG_R10: Context->r10 = Value; return;
        case VMX_EXIT_QUALIFICATION_GENREG_R11: Context->r11 = Value; return;
        case VMX_EXIT_QUALIFICATION_GENREG_R12: Context->r12 = Value; return;
        case VMX_EXIT_QUALIFICATION_GENREG_R13: Context->r13 = Value; return;
        case VMX_EXIT_QUALIFICATION_GENREG_R14: Context->r14 = Value; return;
        case VMX_EXIT_QUALIFICATION_GENREG_R15: Context->r15 = Value; return;
        default: return;
        }
}

FORCEINLINE
STATIC
VOID
__vapic_write_32(_In_ UINT32 Value, _In_ UINT32 Register)
{
        PVIRTUAL_MACHINE_STATE vcpu = &vmm_state[KeGetCurrentProcessorNumber()];
        PVTPR vtpr = (PVTPR)(vcpu->virtual_apic_va + APIC_TASK_PRIORITY);
        vtpr->VirtualTaskPriorityRegister = Value;
        __writecr8(vtpr->VirtualTaskPriorityRegister);
#if DEBUG
        HIGH_IRQL_LOG_SAFE("tpr write: %lx", vtpr->VirtualTaskPriorityRegister);
#endif
}

FORCEINLINE
STATIC
VOID
__vapic_read_32(_In_ PGUEST_CONTEXT                 Context,
                _In_ VMX_EXIT_QUALIFICATION_MOV_CR* Qualification,
                _In_ UINT32                         ApicRegister)
{
        PVIRTUAL_MACHINE_STATE vcpu = &vmm_state[KeGetCurrentProcessorNumber()];
        PVTPR vtpr = (PVTPR)(vcpu->virtual_apic_va + APIC_TASK_PRIORITY);
        WriteValueInContextRegister(Context,
                                    Qualification->GeneralPurposeRegister,
                                    (UINT32)vtpr->VirtualTaskPriorityRegister);
#if DEBUG
        HIGH_IRQL_LOG_SAFE("tpr read: %lx", vtpr->VirtualTaskPriorityRegister);
#endif
}

/*
 * Write the value of the designated general purpose register into the
 * designated control register
 */
STATIC
VOID
DispatchExitReasonMovToCr(_In_ VMX_EXIT_QUALIFICATION_MOV_CR* Qualification,
                          _In_ PGUEST_CONTEXT                 Context)
{
        UINT64 value = RetrieveValueInContextRegister(
            Context, Qualification->GeneralPurposeRegister);

        switch (Qualification->ControlRegister) {
        case VMX_EXIT_QUALIFICATION_REGISTER_CR0:
                VmxVmWrite(VMCS_GUEST_CR0, value);
                VmxVmWrite(VMCS_CTRL_CR0_READ_SHADOW, value);
                return;
        case VMX_EXIT_QUALIFICATION_REGISTER_CR3:
                VmxVmWrite(VMCS_GUEST_CR3, CLEAR_CR3_RESERVED_BIT(value));
                return;
        case VMX_EXIT_QUALIFICATION_REGISTER_CR4:
                VmxVmWrite(VMCS_GUEST_CR4, value);
                VmxVmWrite(VMCS_CTRL_CR4_READ_SHADOW, value);
#if CR8_EXITING
        case VMX_EXIT_QUALIFICATION_REGISTER_CR8:
                __vapic_write_32((UINT32)value, APIC_TASK_PRIORITY);
                return;
#endif
        default: return;
        }
}

/*
 * Write the value of the designated control register in the designated general
 * purpose register
 */
STATIC
VOID
DispatchExitReasonMovFromCr(_In_ VMX_EXIT_QUALIFICATION_MOV_CR* Qualification,
                            _In_ PGUEST_CONTEXT                 Context)
{
        switch (Qualification->ControlRegister) {
        case VMX_EXIT_QUALIFICATION_REGISTER_CR0:
                WriteValueInContextRegister(
                    Context,
                    Qualification->GeneralPurposeRegister,
                    VmxVmRead(VMCS_GUEST_CR0));
                break;
        case VMX_EXIT_QUALIFICATION_REGISTER_CR3:
                WriteValueInContextRegister(
                    Context,
                    Qualification->GeneralPurposeRegister,
                    VmxVmRead(VMCS_GUEST_CR3));
                break;
        case VMX_EXIT_QUALIFICATION_REGISTER_CR4:
                WriteValueInContextRegister(
                    Context,
                    Qualification->GeneralPurposeRegister,
                    VmxVmRead(VMCS_GUEST_CR4));
                break;
#if CR8_EXITING
        case VMX_EXIT_QUALIFICATION_REGISTER_CR8:
                __vapic_read_32(Context, Qualification, APIC_TASK_PRIORITY);
                break;
#endif
        default: break;
        }
}

/*
 * CLTS instruction clears the Task-Switched flag in CR0
 *
 * https://www.felixcloutier.com/x86/clts
 *
 * The CLTS instruction causes a VM exit if the bits in position 3
 * (corresponding to CR0.TS) are set in both the CR0 guest/host mask and the CR0
 * read shadow.
 */
STATIC
VOID
DispatchExitReasonCLTS(_In_ VMX_EXIT_QUALIFICATION_MOV_CR* Qualification,
                       _In_ PGUEST_CONTEXT                 Context)
{
        CR0 cr0                 = {0};
        cr0.AsUInt              = VmxVmRead(VMCS_GUEST_CR0);
        cr0.Fields.TaskSwitched = FALSE;

        VmxVmWrite(VMCS_GUEST_CR0, cr0.AsUInt);
        VmxVmWrite(VMCS_CTRL_CR0_READ_SHADOW, cr0.AsUInt);
}

STATIC
BOOLEAN
DispatchExitReasonControlRegisterAccess(_In_ PGUEST_CONTEXT Context)
{
        VMX_EXIT_QUALIFICATION_MOV_CR qualification = {0};
        qualification.AsUInt = VmxVmRead(VMCS_EXIT_QUALIFICATION);

        switch (qualification.AccessType) {
        case VMX_EXIT_QUALIFICATION_ACCESS_MOV_TO_CR:
                DispatchExitReasonMovToCr(&qualification, Context);
                break;
        case VMX_EXIT_QUALIFICATION_ACCESS_MOV_FROM_CR:
                DispatchExitReasonMovFromCr(&qualification, Context);
                break;
        case VMX_EXIT_QUALIFICATION_ACCESS_CLTS:
                DispatchExitReasonCLTS(&qualification, Context);
                break;
        case VMX_EXIT_QUALIFICATION_ACCESS_LMSW: break;
        default: break;
        }

        /*
         * MOV to CR8 and MOV from CR8 are trap-like exits, where the
         * instruction completes before the vmx host handler is invoked, hence
         * we shouldnt increment the guest rip.
         */
        if (qualification.ControlRegister ==
            VMX_EXIT_QUALIFICATION_REGISTER_CR8) {
                // DEBUG_LOG("cr8 exiting");
                return TRUE;
        }

        return FALSE;
}

FORCEINLINE
STATIC
VOID
DispatchExitReasonINVD(_In_ PGUEST_CONTEXT GuestState)
{
        /* this is how hyper-v performs their invd */
        __wbinvd();
}

/*
 * Intel reserves CPUID Function levels 0x40000000 - 0x400000FF
 * for software use. This allows us to setup our own CPUID based
 * hypercall interface. For now we simple return the vendor, in
 * this case i love fortnite!
 */
FORCEINLINE
STATIC
BOOLEAN
IsCpuidFunctionAtHypervisorAltitude(_In_ UINT64 Rax)
{
        return Rax >= VMX_CPUID_FUNCTION_LOW && Rax <= VMX_CPUID_FUNCTION_HIGH
                   ? TRUE
                   : FALSE;
}

FORCEINLINE
STATIC
VOID
DispatchExitReasonCPUID(_In_ PGUEST_CONTEXT GuestState)
{
        /* todo: implement some sort of caching mechanism */
        PVIRTUAL_MACHINE_STATE state =
            &vmm_state[KeGetCurrentProcessorNumber()];

        if (IsCpuidFunctionAtHypervisorAltitude(GuestState->rax)) {
                switch (GuestState->rax) {
                case CPUID_HYPERVISOR_INTERFACE_VENDOR:
                        state->cache.cpuid.value[CPUID_EAX] = 'i';
                        state->cache.cpuid.value[CPUID_EBX] = 'evol';
                        state->cache.cpuid.value[CPUID_ECX] = 'trof';
                        state->cache.cpuid.value[CPUID_EDX] = 'etin';
                default:
#if DEBUG
                        HIGH_IRQL_LOG_SAFE(
                            "Invalid HV CPUID Function identifier passed.");
#endif
                        break;
                }
        }
        else {
                __cpuidex(state->cache.cpuid.value,
                          (INT32)GuestState->rax,
                          (INT32)GuestState->rcx);
        }

        GuestState->rax = state->cache.cpuid.value[CPUID_EAX];
        GuestState->rbx = state->cache.cpuid.value[CPUID_EBX];
        GuestState->rcx = state->cache.cpuid.value[CPUID_ECX];
        GuestState->rdx = state->cache.cpuid.value[CPUID_EDX];
}

FORCEINLINE
STATIC
VOID
DispatchExitReasonWBINVD(_In_ PGUEST_CONTEXT Context)
{
        __wbinvd();
}

FORCEINLINE
STATIC
VOID
DispatchVmCallTerminateVmx()
{
        PVIRTUAL_MACHINE_STATE state = &vmm_state[KeGetCurrentProcessorIndex()];
        InterlockedExchange(&state->exit_state.exit_vmx, TRUE);
}

FORCEINLINE
STATIC
NTSTATUS
DispatchVmCallPing()
{
        return STATUS_SUCCESS;
}

STATIC
NTSTATUS
VmCallDispatcher(_In_ UINT64     HypercallId,
                 _In_opt_ UINT64 OptionalParameter1,
                 _In_opt_ UINT64 OptionalParameter2,
                 _In_opt_ UINT64 OptionalParameter3)
{
        switch (HypercallId) {
        case VMX_HYPERCALL_TERMINATE_VMX: DispatchVmCallTerminateVmx(); break;
        case VMX_HYPERCALL_PING: return DispatchVmCallPing();
        default: break;
        }

        return STATUS_SUCCESS;
}

FORCEINLINE
STATIC
VOID
RestoreGuestStateOnTerminateVmx(PVIRTUAL_MACHINE_STATE State)
{
        /*
         * Before we execute vmxoff, store the guests rip and rsp in our vmxoff
         * state structure, this will allow us to use these values in the vmxoff
         * part of our vmx exit handler to properly restore the stack and
         * instruction pointer after we execute vmxoff
         *
         * The reason we must do this is since we are executing vmxoff, the rip
         * and rsp will no longer be automatically updated by hardware from the
         * vmcs, hence we need to save the 2 values and update the registers
         * with the values during our exit handler before we call vmxoff
         */
        State->exit_state.guest_rip = VmxVmRead(VMCS_GUEST_RIP);
        State->exit_state.guest_rsp = VmxVmRead(VMCS_GUEST_RSP);

        /*
         * Since vmx root operation makes use of the system cr3, we need to
         * ensure we write the value of the guests previous cr3 before the exit
         * took place to ensure they have access to the correct dtb
         */
        __writecr3(VmxVmRead(VMCS_GUEST_CR3));

        /*
         * Do the same with the FS and GS base
         */

        __writemsr(IA32_FS_BASE, VmxVmRead(VMCS_GUEST_FS_BASE));
        __writemsr(IA32_GS_BASE, VmxVmRead(VMCS_GUEST_GS_BASE));

        /*
         * Write back the guest gdtr and idtrs
         */
        SEGMENT_DESCRIPTOR_REGISTER_64 gdtr = {0};
        gdtr.BaseAddress                    = VmxVmRead(VMCS_GUEST_GDTR_BASE);
        gdtr.Limit                          = VmxVmRead(VMCS_GUEST_GDTR_LIMIT);
        __lgdt(&gdtr);

        SEGMENT_DESCRIPTOR_REGISTER_64 idtr = {0};
        idtr.BaseAddress                    = VmxVmRead(VMCS_GUEST_IDTR_BASE);
        idtr.Limit                          = VmxVmRead(VMCS_GUEST_IDTR_LIMIT);
        __lidt(&idtr);

        /*
        Execute the vmxoff instruction, leaving vmx operation
        */
        __vmx_off();
}

FORCEINLINE
STATIC
VOID
DispatchExitReasonTprBelowThreshold(_In_ PGUEST_CONTEXT Context)
{
        DEBUG_LOG("exit reason tpr threshold");
        DEBUG_LOG("guest rip: %llx", VmxVmRead(VMCS_GUEST_RIP));
        PVIRTUAL_MACHINE_STATE vcpu = &vmm_state[KeGetCurrentProcessorNumber()];
        // VTPR*                  vtpr         = vcpu->virtual_apic_va +
        // APIC_TASK_PRIORITY; vtpr->VirtualTaskPriorityRegister   = 0;
        // vtpr->TaskPriorityRegisterThreshold = 1;
}

FORCEINLINE
STATIC
VOID
InjectExceptionOnVmEntry(VMEXIT_INTERRUPT_INFORMATION* ExitInterrupt)
{
        VMENTRY_INTERRUPT_INFORMATION intr = {
            .Vector           = ExitInterrupt->Vector,
            .DeliverErrorCode = ExitInterrupt->ErrorCodeValid,
            .InterruptionType = ExitInterrupt->InterruptionType,
            .Valid            = ExitInterrupt->Valid};

        /*
         * If bits 31 (Valid) and 11 (ErrorCodeValid) the vm-exit interruption
         * error code VMCS field receives the error code that would've been
         * pushed onto the stack by the exception.
         */
        if (ExitInterrupt->Valid && ExitInterrupt->ErrorCodeValid) {
                VmxVmWrite(VMCS_CTRL_VMENTRY_EXCEPTION_ERROR_CODE,
                           VmxVmRead(VMCS_VMEXIT_INTERRUPTION_ERROR_CODE));
        }

        VmxVmWrite(VMCS_CTRL_VMENTRY_INTERRUPTION_INFORMATION_FIELD,
                   intr.AsUInt);
}

/*
 * If vm-entry successfully injects an event with interruption type external
 * interrupt, NMI or hardware exception the current guest RIP is pushed onto the
 * stack.
 *
 * if vm-entry successfully injects an event with interruption type software
 * interrupt, privileged software exception or software exception the current
 * guest RIP is incremented by the vm-entry instruction length before being
 * pushed onto the stack, hence we do not advance the guest rip in this case.
 */
FORCEINLINE
STATIC
BOOLEAN
ShouldExceptionAdvanceGuestRip(VMEXIT_INTERRUPT_INFORMATION* ExitInformation)
{
        if (ExitInformation->InterruptionType == SoftwareInterrupt ||
            ExitInformation->InterruptionType == PrivilegedSoftwareException ||
            ExitInformation->InterruptionType == SoftwareException)
                return FALSE;

        return TRUE;
}

FORCEINLINE
STATIC
BOOLEAN
DispatchExitReasonExceptionOrNmi(_In_ PGUEST_CONTEXT Context)
{
        VMEXIT_INTERRUPT_INFORMATION intr = {
            .AsUInt = VmxVmRead(VMCS_VMEXIT_INTERRUPTION_INFORMATION)};

#if DEBUG
        HIGH_IRQL_LOG_SAFE("Core: %lx - Vector: %lx, Interruption type: %lx",
                           KeGetCurrentProcessorNumber(),
                           intr.Vector,
                           intr.InterruptionType);
#endif

        switch (intr.Vector) {
        case EXCEPTION_DIVIDED_BY_ZERO: InjectExceptionOnVmEntry(&intr); break;
        }

        return ShouldExceptionAdvanceGuestRip(&intr);
}

/*
 * If we are delivering an interruption type equal to 7 (Other) and the vector
 * field is 0, vm-entry will cause an MTF vm-exit to be pending on the
 * instruction boundary. This will occur even if the monitor trap flag VMCS
 * control is set to 0.
 */
FORCEINLINE
STATIC
VOID
DispatchExitReasonMonitorTrapFlag(_In_ PGUEST_CONTEXT Context)
{
        PVIRTUAL_MACHINE_STATE vcpu = &vmm_state[KeGetCurrentProcessorNumber()];
        /*
         * Since we don't set the monitor trap flag vmcs ctrl, lets simply clear
         * the mtf flag for the guest and continue execution.
         */
        if (!vcpu->proc_ctls.MonitorTrapFlag) {
                RFLAGS flags    = {.AsUInt = Context->eflags};
                flags.TrapFlag  = FALSE;
                Context->eflags = flags.AsUInt;
        }
        else {
                /* For now, just bugcheck */
                KeBugCheckEx(VMX_BUGCHECK_INVALID_MTF_EXIT,
                             VmxVmRead(VMCS_GUEST_RIP),
                             Context->eflags,
                             vcpu->proc_ctls.AsUInt,
                             0);
        }
}

FORCEINLINE
STATIC
VOID
DispatchExitReasonWrmsr(_In_ PGUEST_CONTEXT Context)
{
        LARGE_INTEGER msr = {0};
        msr.LowPart       = (UINT32)Context->rax;
        msr.HighPart      = (UINT32)Context->rdx;
        __writemsr((UINT32)Context->rcx, msr.QuadPart);
#if DEBUG
        HIGH_IRQL_LOG_SAFE(
            "Wrmsr - rax: %llx, rcx: %llx", Context->rax, Context->rcx);
#endif
}

#define X2APIC_MSR_LOW  0x800
#define X2APIC_MSR_HIGH 0x83f

FORCEINLINE
STATIC
BOOLEAN
IsMsrReadX2Apic(UINT32 Ecx)
{
        return Ecx >= X2APIC_MSR_LOW && Ecx <= X2APIC_MSR_HIGH ? TRUE : FALSE;
}

FORCEINLINE
STATIC
VOID
DispatchExitReasonRdmsr(_In_ PGUEST_CONTEXT Context)
{
        LARGE_INTEGER msr = {0};
        msr.QuadPart      = __readmsr((UINT32)Context->rcx);
        Context->rax      = msr.LowPart;
        Context->rdx      = msr.HighPart;
#if DEBUG
        HIGH_IRQL_LOG_SAFE("Rdmsr: rcx: %llx", Context->rcx);
#endif
}

BOOLEAN
VmExitDispatcher(_In_ PGUEST_CONTEXT Context)
{
        UINT64                 additional_rip_offset = 0;
        PVIRTUAL_MACHINE_STATE state = &vmm_state[KeGetCurrentProcessorIndex()];

        switch (VmxVmRead(VMCS_EXIT_REASON)) {
        case VMX_EXIT_REASON_EXECUTE_CPUID:
                DispatchExitReasonCPUID(Context);
                break;
        case VMX_EXIT_REASON_EXECUTE_INVD:
                DispatchExitReasonINVD(Context);
                break;
        case VMX_EXIT_REASON_EXECUTE_VMCALL:
                Context->rax = VmCallDispatcher(
                    Context->rcx, Context->rdx, Context->r8, Context->r9);
                break;
        case VMX_EXIT_REASON_MOV_CR:
                if (DispatchExitReasonControlRegisterAccess(Context))
                        goto no_rip_increment;
                break;
        case VMX_EXIT_REASON_EXECUTE_WBINVD:
                DispatchExitReasonWBINVD(Context);
                break;

        /*
         * TPR_BELOW_THRESHOLD is a trap-like exit and will perform the
         * exit-casuing instruction before invoking our handler, hence we
         * shouldn't increment the rip.
         */
        case VMX_EXIT_REASON_TPR_BELOW_THRESHOLD:
                DispatchExitReasonTprBelowThreshold(Context);
                goto no_rip_increment;

        /*
         * If DispatchExitReasonExceptionOrNmi returns FALSE, we don't advanced
         * the guest rip, else we do as normal.
         */
        case VMX_EXIT_REASON_EXCEPTION_OR_NMI:
                if (!DispatchExitReasonExceptionOrNmi(Context))
                        goto no_rip_increment;
                break;

        case VMX_EXIT_REASON_MONITOR_TRAP_FLAG:
                DispatchExitReasonMonitorTrapFlag(Context);
                goto no_rip_increment;
        case VMX_EXIT_REASON_EXECUTE_WRMSR:
                DispatchExitReasonWrmsr(Context);
                break;
        case VMX_EXIT_REASON_EXECUTE_RDMSR:
                DispatchExitReasonRdmsr(Context);
                break;
        default: break;
        }

        /*
         * Increment our guest rip by the size of the exiting instruction since
         * we've processed it
         */
        IncrementGuestRip();

no_rip_increment:
        /*
         * If we are indeed exiting VMX operation, return TRUE to indicate to
         * our handler that we have indeed exited VMX operation.
         */
        if (InterlockedExchange(&state->exit_state.exit_vmx,
                                state->exit_state.exit_vmx)) {
                RestoreGuestStateOnTerminateVmx(state);
                return TRUE;
        }

        /* continue vmx operation as usual */
        return FALSE;
}