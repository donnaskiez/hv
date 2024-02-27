#include "dispatch.h"

#include "vmx.h"
#include "vmcs.h"
#include <intrin.h>
#include "arch.h"
#include "log.h"

FORCEINLINE
VOID
InjectHwExceptionIntoGuest(UINT32 Vector)
{
        VMENTRY_INTERRUPT_INFORMATION interrupt = {0};
        interrupt.Vector                        = Vector;
        interrupt.InterruptionType              = HardwareException;
        interrupt.DeliverErrorCode              = FALSE;
        interrupt.Valid                         = TRUE;

        VmxVmWrite(VMCS_CTRL_VMENTRY_INTERRUPTION_INFORMATION_FIELD, interrupt.AsUInt);
}

FORCEINLINE
VOID
InjectHwExceptionIntoGuestWithErrorCode(UINT32 Vector)
{
        VMENTRY_INTERRUPT_INFORMATION interrupt = {0};
        interrupt.Vector                        = Vector;
        interrupt.InterruptionType              = HardwareException;
        interrupt.DeliverErrorCode              = TRUE;
        interrupt.Valid                         = TRUE;

        VmxVmWrite(VMCS_CTRL_VMENTRY_INTERRUPTION_INFORMATION_FIELD, interrupt.AsUInt);
        VmxVmWrite(VMCS_CTRL_VMENTRY_EXCEPTION_ERROR_CODE, interrupt.AsUInt);
}

FORCEINLINE
VOID
InjectNmiIntoGuest()
{
        VMENTRY_INTERRUPT_INFORMATION interrupt = {0};
        interrupt.Vector                        = Nmi;
        interrupt.InterruptionType              = NonMaskableInterrupt;
        interrupt.DeliverErrorCode              = FALSE;
        interrupt.Valid                         = TRUE;

        VmxVmWrite(VMCS_CTRL_VMENTRY_INTERRUPTION_INFORMATION_FIELD, interrupt.AsUInt);
}

VOID
IncrementGuestRip()
{
        VmxVmWrite(VMCS_GUEST_RIP,
                   VmxVmRead(VMCS_GUEST_RIP) + VmxVmRead(VMCS_VMEXIT_INSTRUCTION_LENGTH));
}

STATIC
UINT64
RetrieveValueInContextRegister(_In_ PGUEST_CONTEXT Context, _In_ UINT32 Register)
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

STATIC
VOID
WriteValueInContextRegister(_In_ PGUEST_CONTEXT Context, _In_ UINT32 Register, _In_ UINT64 Value)
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

/*
 * Write the value of the designated general purpose register into the
 * designated control register
 */
STATIC
VOID
DispatchExitReasonMovToCr(_In_ VMX_EXIT_QUALIFICATION_MOV_CR* Qualification,
                          _In_ PGUEST_CONTEXT                 Context)
{
        UINT64 value =
            RetrieveValueInContextRegister(Context, Qualification->GeneralPurposeRegister);

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
                return;
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
        // clang-format off

        switch (Qualification->ControlRegister) {
        case VMX_EXIT_QUALIFICATION_REGISTER_CR0: WriteValueInContextRegister(Context, Qualification->GeneralPurposeRegister, VmxVmRead(VMCS_GUEST_CR0)); break;
        case VMX_EXIT_QUALIFICATION_REGISTER_CR3: WriteValueInContextRegister(Context, Qualification->GeneralPurposeRegister, VmxVmRead(VMCS_GUEST_CR3)); break;
        case VMX_EXIT_QUALIFICATION_REGISTER_CR4: WriteValueInContextRegister(Context, Qualification->GeneralPurposeRegister, VmxVmRead(VMCS_GUEST_CR4)); break;
        default: break;
        }

        // clang-format on
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
VOID
DispatchExitReasonControlRegisterAccess(_In_ PGUEST_CONTEXT Context)
{
        VMX_EXIT_QUALIFICATION_MOV_CR qualification = {0};
        qualification.AsUInt                        = VmxVmRead(VMCS_EXIT_QUALIFICATION);

        // clang-format off

        switch (qualification.AccessType) {
        case VMX_EXIT_QUALIFICATION_ACCESS_MOV_TO_CR:    DispatchExitReasonMovToCr(&qualification, Context);     break;
        case VMX_EXIT_QUALIFICATION_ACCESS_MOV_FROM_CR:  DispatchExitReasonMovFromCr(&qualification, Context);   break;
        case VMX_EXIT_QUALIFICATION_ACCESS_CLTS:         DispatchExitReasonCLTS(&qualification, Context);        break;
        case VMX_EXIT_QUALIFICATION_ACCESS_LMSW:         break;
        default:                                         break;
        }

        // clang-format on
}

STATIC
VOID
DispatchExitReasonINVD(_In_ PGUEST_CONTEXT GuestState)
{
        /* this is how hyper-v performs their invd */
        __wbinvd();
}

STATIC
VOID
DispatchExitReasonCPUID(_In_ PGUEST_CONTEXT GuestState)
{
        /*
         * todo: implement some sort of caching mechanism
         */
        PVIRTUAL_MACHINE_STATE state = &vmm_state[KeGetCurrentProcessorNumber()];

        __cpuidex(state->cache.cpuid.value, (INT32)GuestState->rax, (INT32)GuestState->rcx);

        GuestState->rax = state->cache.cpuid.value[0];
        GuestState->rbx = state->cache.cpuid.value[1];
        GuestState->rcx = state->cache.cpuid.value[2];
        GuestState->rdx = state->cache.cpuid.value[3];
}

STATIC
VOID
DispatchExitReasonWBINVD(_In_ PGUEST_CONTEXT Context)
{
        __wbinvd();
}

VOID
DispatchVmCallTerminateVmx()
{
        PVIRTUAL_MACHINE_STATE state = &vmm_state[KeGetCurrentProcessorIndex()];
        InterlockedExchange(&state->exit_state.exit_vmx, TRUE);
}

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
        // clang-format off
        switch (HypercallId) {
        case VMX_HYPERCALL_TERMINATE_VMX:       DispatchVmCallTerminateVmx(); break;
        case VMX_HYPERCALL_PING:                return DispatchVmCallPing();
        default: break;
        }
        // clang-format on      

        return STATUS_SUCCESS;
}

FORCEINLINE
VOID
RestoreGuestStateOnTerminateVmx(PVIRTUAL_MACHINE_STATE State)
{
        /*
         * Before we execute vmxoff, store the guests rip and rsp in our vmxoff state
         * structure, this will allow us to use these values in the vmxoff part of our vmx
         * exit handler to properly restore the stack and instruction pointer after we
         * execute vmxoff
         *
         * The reason we must do this is since we are executing vmxoff, the rip and rsp will
         * no longer be automatically updated by hardware from the vmcs, hence we need to
         * save the 2 values and update the registers with the values during our exit
         * handler before we call vmxoff
         */
        State->exit_state.guest_rip = VmxVmRead(VMCS_GUEST_RIP);
        State->exit_state.guest_rsp = VmxVmRead(VMCS_GUEST_RSP);

        /*
         * Since vmx root operation makes use of the system cr3, we need to ensure we write
         * the value of the guests previous cr3 before the exit took place to ensure they
         * have access to the correct dtb
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

BOOLEAN
VmExitDispatcher(_In_ PGUEST_CONTEXT Context)
{
        UINT64                 additional_rip_offset = 0;
        PVIRTUAL_MACHINE_STATE state                 = &vmm_state[KeGetCurrentProcessorIndex()];

        // clang-format off
        switch (VmxVmRead(VMCS_EXIT_REASON)) {
        case VMX_EXIT_REASON_EXECUTE_CPUID:     DispatchExitReasonCPUID(Context);                                                       break;
        case VMX_EXIT_REASON_EXECUTE_INVD:      DispatchExitReasonINVD(Context);                                                        break;
        case VMX_EXIT_REASON_EXECUTE_VMCALL:    Context->rax = VmCallDispatcher(Context->rcx, Context->rdx, Context->r8, Context->r9);  break;
        case VMX_EXIT_REASON_MOV_CR:            DispatchExitReasonControlRegisterAccess(Context);                                       break;
        case VMX_EXIT_REASON_EXECUTE_WBINVD:    DispatchExitReasonWBINVD(Context);                                                      break;
        default: break;
        }
        // clang-format on

        /* Increment our guest rip by the size of the exiting instruction since we've processed it
         */
        IncrementGuestRip();

        /*
         * If we are in DEBUG mode, lets queue our DPC routine that will flush our logs to the
         * debugger.
         */
#if DEBUG
        if (CheckToFlushLogs(state)) {
                KeInsertQueueDpc(&state->log_state.dpc, NULL, NULL);
        }
#endif

        /*
         * If we are indeed exiting VMX operation, return TRUE to indicate to our handler that we
         * have indeed exited VMX operation.
         */
        if (InterlockedExchange(&state->exit_state.exit_vmx, state->exit_state.exit_vmx)) {
                RestoreGuestStateOnTerminateVmx(state);
                return TRUE;
        }

        /* continue vmx operation as usual */
        return FALSE;
}