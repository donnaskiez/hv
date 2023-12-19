#include "dispatch.h"

#include "Zydis/Zydis.h"
#include "vmx.h"
#include "vmcs.h"
#include "pipeline.h"
#include <intrin.h>
#include "arch.h"

VOID
IncrementGuestRip(_In_ UINT64 InstructionOffset)
{
        VmcsWriteGuestRip(VmcsReadGuestRip() + VmcsReadInstructionLength() + InstructionOffset);
}

STATIC
UINT64
RetrieveValueInContextRegister(_In_ PGUEST_CONTEXT Context, _In_ UINT32 Register)
{
        switch (Register)
        {
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
        switch (Register)
        {
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
DispatchExitReasonMovToCr(_In_ PMOV_CR_QUALIFICATION Qualification, _In_ PGUEST_CONTEXT Context)
{
        UINT64 value = RetrieveValueInContextRegister(Context, Qualification->Fields.Register);

        switch (Qualification->Fields.ControlRegister)
        {
        case CONTROL_REGISTER_0:
                VmcsWriteGuestCr0(value);
                VmcsWriteGuestCr0ReadShadow(value);
                return;
        case CONTROL_REGISTER_3: VmcsWriteGuestCr3((value & ~(1ull << 63))); return;
        case CONTROL_REGISTER_4:
                VmcsWriteGuestCr4(value);
                VmcsWriteGuestCr4ReadShadow(value);
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
DispatchExitReasonMovFromCr(_In_ PMOV_CR_QUALIFICATION Qualification, _In_ PGUEST_CONTEXT Context)
{
        switch (Qualification->Fields.ControlRegister)
        {
        case CONTROL_REGISTER_0:
                WriteValueInContextRegister(
                    Context, Qualification->Fields.Register, VmcsReadGuestCr0());
                break;
        case CONTROL_REGISTER_3:
                WriteValueInContextRegister(
                    Context, Qualification->Fields.Register, VmcsReadGuestCr3());
                break;
        case CONTROL_REGISTER_4:
                WriteValueInContextRegister(
                    Context, Qualification->Fields.Register, VmcsReadGuestCr4());
                break;
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
DispatchExitReasonCLTS(_In_ PMOV_CR_QUALIFICATION Qualification, _In_ PGUEST_CONTEXT Context)
{
        CR0 cr0                 = {0};
        cr0.AsUInt              = VmcsReadGuestCr0();
        cr0.Fields.TaskSwitched = FALSE;

        VmcsWriteGuestCr0(cr0.AsUInt);
        VmcsWriteGuestCr0ReadShadow(cr0.AsUInt);
}

/*
 * Table 27-3: Bits 11:8 tell us which register was used.
 *
 *   For MOV CR, the general-purpose register:
 *   0 = RAX
 *   1 = RCX
 *   2 = RDX
 *   3 = RBX
 *   4 = RSP
 *   5 = RBP
 *   6 = RSI
 *   7 = RDI
 *
 * 8–15 represent R8–R15, respectively (used only on processors that support
 * Intel 64 architecture)
 *
 * Bits 3:0 tell us which control register is the subject of this exit:
 *
 *   0 = CR0
 *   3 = CR3
 *   4 = CR4
 *   8 = CR8
 */
STATIC
VOID
DispatchExitReasonControlRegisterAccess(_In_ PGUEST_CONTEXT Context)
{
        MOV_CR_QUALIFICATION qualification = {0};

        qualification.All = VmcsReadExitQualification();

        switch (qualification.Fields.AccessType)
        {
        case TYPE_MOV_TO_CR: DispatchExitReasonMovToCr(&qualification, Context); break;
        case TYPE_MOV_FROM_CR: DispatchExitReasonMovFromCr(&qualification, Context); break;
        case TYPE_CLTS: DispatchExitReasonCLTS(&qualification, Context); break;
        case TYPE_LMSW: break;
        default: break;
        }
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
VmCallDispatcher(_In_ UINT64 VmCallNumber,
                 _In_ UINT64 OptionalParameter1,
                 _In_ UINT64 OptionalParameter2,
                 _In_ UINT64 OptionalParameter3)
{
        DEBUG_LOG("Vmcall number: %llx", VmCallNumber);

        switch (VmCallNumber)
        {
        case TERMINATE_VMX: DispatchVmCallTerminateVmx(); break;
        case TEST: break;
        default: break;
        }

        return STATUS_SUCCESS;
}

BOOLEAN
VmExitDispatcher(_In_ PGUEST_CONTEXT Context)
{
        UINT64                 additional_rip_offset = 0;
        PVIRTUAL_MACHINE_STATE state                 = &vmm_state[KeGetCurrentProcessorIndex()];

        switch (VmcsReadExitReason())
        {
        case EXIT_REASON_CPUID: DispatchExitReasonCPUID(Context); break;
        case EXIT_REASON_INVD: DispatchExitReasonINVD(Context); break;
        case EXIT_REASON_VMCALL:
                Context->rax =
                    VmCallDispatcher(Context->rcx, Context->rdx, Context->r8, Context->r9);
                break;
        case EXIT_REASON_CR_ACCESS: DispatchExitReasonControlRegisterAccess(Context); break;
        case EXIT_REASON_WBINVD: DispatchExitReasonWBINVD(Context); break;
        default: break;
        }

        /*
         * Once we have processed the initial instruction causing the vmexit, we
         * can translate the next instruction. Once decoded, if its a vm-exit
         * causing instruction we can process that instruction and then advance
         * the rip by the size of the 2 exit-inducing instructions - saving us 1
         * vm exit (2 minus 1 = 1).
         */

#pragma warning(push)
#pragma warning(disable : 6387)

        // HandleFutureInstructions(
        //     (PVOID)(VmcsReadExitInstructionRip() + VmcsReadInstructionLength()),
        //     Context,
        //     &additional_rip_offset);

#pragma warning(pop)

        /*
         * Increment our guest rip by the size of the exiting instruction since we've processed it
         */
        IncrementGuestRip(0);

        if (InterlockedExchange(&state->exit_state.exit_vmx, state->exit_state.exit_vmx))
        {
                DEBUG_LOG("Exiting VMX operation");

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
                state->exit_state.guest_rip = VmcsReadGuestRip();
                state->exit_state.guest_rsp = VmcsReadGuestRsp();

                /*
                 * Since vmx root operation makes use of the system cr3, we need to ensure we write
                 * the value of the guests previous cr3 before the exit took place to ensure they
                 * have access to the correct dtb
                 */
                __writecr3(VmcsReadGuestCr3());

                /*
                 * Do the same with the FS and GS base
                 */
                __writemsr(MSR_FS_BASE, VmcsReadGuestFsBase());
                __writemsr(MSR_GS_BASE, VmcsReadGuestGsBase());

                /*
                 * Write back the guest gdtr and idtrs
                 */
                SEGMENT_DESCRIPTOR_REGISTER gdtr = {0};
                gdtr.base_address                = VmcsReadGuestGdtrBase();
                gdtr.limit                       = VmcsReadGuestGdtrLimit();
                __lgdt(&gdtr);

                SEGMENT_DESCRIPTOR_REGISTER idtr = {0};
                idtr.base_address                = VmcsReadGuestIdtrBase();
                idtr.limit                       = VmcsReadGuestIdtrLimit();
                __lidt(&idtr);

                /*
                Execute the vmxoff instruction, leaving vmx operation
                */
                __vmx_off();

                /*
                 * Return true, indicating that we are ready to leave vmx operation in our exit
                 * handler.
                 */
                return TRUE;
        }

        /* continue vmx operation as usual */
        return FALSE;
}