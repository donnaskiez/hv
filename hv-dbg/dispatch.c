#include "dispatch.h"

#include "Zydis/Zydis.h"
#include "vmx.h"
#include "vmcs.h"
#include "pipeline.h"

VOID
ResumeToNextInstruction(
        _In_ UINT64 InstructionOffset
)
{
        VmcsWriteGuestRip(VmcsReadExitInstructionRip() + VmcsReadInstructionLength() + InstructionOffset);
}

VOID
VmResumeInstruction()
{
        __vmx_vmresume();

        /*
        * As always if vmresume succeeds guest execution will continue and we won't reach here
        * since the next execution of host code will be the exit handler rip.
        */
        DEBUG_ERROR("vmresume failed with status: %lx", VmcsReadInstructionErrorCode());
}

STATIC
UINT64
RetrieveValueInContextRegister(
        _In_ PGUEST_CONTEXT Context,
        _In_ UINT32 Register
)
{
        switch (Register)
        {
        case VMX_EXIT_QUALIFICATION_GENREG_RAX: { return Context->rax; }
        case VMX_EXIT_QUALIFICATION_GENREG_RCX: { return Context->rcx; }
        case VMX_EXIT_QUALIFICATION_GENREG_RDX: { return Context->rdx; }
        case VMX_EXIT_QUALIFICATION_GENREG_RBX: { return Context->rbx; }
        case VMX_EXIT_QUALIFICATION_GENREG_RSP: { return Context->rsp; }
        case VMX_EXIT_QUALIFICATION_GENREG_RBP: { return Context->rbp; }
        case VMX_EXIT_QUALIFICATION_GENREG_RSI: { return Context->rsi; }
        case VMX_EXIT_QUALIFICATION_GENREG_RDI: { return Context->rdi; }
        case VMX_EXIT_QUALIFICATION_GENREG_R8:  { return Context->r8; }
        case VMX_EXIT_QUALIFICATION_GENREG_R9:  { return Context->r9; }
        case VMX_EXIT_QUALIFICATION_GENREG_R10: { return Context->r10; }
        case VMX_EXIT_QUALIFICATION_GENREG_R11: { return Context->r11; }
        case VMX_EXIT_QUALIFICATION_GENREG_R12: { return Context->r12; }
        case VMX_EXIT_QUALIFICATION_GENREG_R13: { return Context->r13; }
        case VMX_EXIT_QUALIFICATION_GENREG_R14: { return Context->r14; }
        case VMX_EXIT_QUALIFICATION_GENREG_R15: { return Context->r15; }
        default: { return 0; }
        }
}

STATIC
VOID
WriteValueInContextRegister(
        _In_ PGUEST_CONTEXT Context,
        _In_ UINT32 Register,
        _In_ UINT64 Value
)
{
        switch (Register)
        {
        case VMX_EXIT_QUALIFICATION_GENREG_RAX: { Context->rax = Value; return; }
        case VMX_EXIT_QUALIFICATION_GENREG_RCX: { Context->rcx = Value; return; }
        case VMX_EXIT_QUALIFICATION_GENREG_RDX: { Context->rdx = Value; return; }
        case VMX_EXIT_QUALIFICATION_GENREG_RBX: { Context->rbx = Value; return; }
        case VMX_EXIT_QUALIFICATION_GENREG_RSP: { Context->rsp = Value; return; }
        case VMX_EXIT_QUALIFICATION_GENREG_RBP: { Context->rbp = Value; return; }
        case VMX_EXIT_QUALIFICATION_GENREG_RSI: { Context->rsi = Value; return; }
        case VMX_EXIT_QUALIFICATION_GENREG_RDI: { Context->rdi = Value; return; }
        case VMX_EXIT_QUALIFICATION_GENREG_R8:  { Context->r8 = Value; return; }
        case VMX_EXIT_QUALIFICATION_GENREG_R9:  { Context->r9 = Value; return; }
        case VMX_EXIT_QUALIFICATION_GENREG_R10: { Context->r10 = Value; return; }
        case VMX_EXIT_QUALIFICATION_GENREG_R11: { Context->r11 = Value; return; }
        case VMX_EXIT_QUALIFICATION_GENREG_R12: { Context->r12 = Value; return; }
        case VMX_EXIT_QUALIFICATION_GENREG_R13: { Context->r13 = Value; return; }
        case VMX_EXIT_QUALIFICATION_GENREG_R14: { Context->r14 = Value; return; }
        case VMX_EXIT_QUALIFICATION_GENREG_R15: { Context->r15 = Value; return; }
        default: { return; }
        }
}

/*
* Write the value of the designated general purpose register into the designated control register
*/
STATIC
VOID
DispatchExitReasonMovToCr(
        _In_ PMOV_CR_QUALIFICATION Qualification,
        _In_ PGUEST_CONTEXT Context
)
{
        UINT64 value = RetrieveValueInContextRegister(Context, Qualification->Fields.Register);

        switch (Qualification->Fields.ControlRegister)
        {
        case CONTROL_REGISTER_0: { VmcsWriteGuestCr0(value); VmcsWriteGuestCr0ReadShadow(value); break; }
        case CONTROL_REGISTER_3: { VmcsWriteGuestCr3((value & ~(1ull << 63))); break; }
        case CONTROL_REGISTER_4: { VmcsWriteGuestCr4(value); VmcsWriteGuestCr4ReadShadow(value); break; }
        default: { break; }
        }
}

/*
* Write the value of the designated control register in the designated general purpose register
*/
STATIC
VOID
DispatchExitReasonMovFromCr(
        _In_ PMOV_CR_QUALIFICATION Qualification,
        _In_ PGUEST_CONTEXT Context
)
{
        switch (Qualification->Fields.ControlRegister)
        {
        case CONTROL_REGISTER_0: { 
                WriteValueInContextRegister(Context, Qualification->Fields.Register, VmcsReadGuestCr0()); break; }
        case CONTROL_REGISTER_3: { 
                WriteValueInContextRegister(Context, Qualification->Fields.Register, VmcsReadGuestCr3()); break; }
        case CONTROL_REGISTER_4: { 
                WriteValueInContextRegister(Context, Qualification->Fields.Register, VmcsReadGuestCr4()); break; }
        default: { break; }
        }
}

/*
* Table 27-3: Bits 11:8 tell us which register was used.
* 
* For MOV CR, the general-purpose register:
* 0 = RAX
* 1 = RCX
* 2 = RDX
* 3 = RBX
* 4 = RSP
* 5 = RBP
* 6 = RSI
* 7 = RDI
* 8–15 represent R8–R15, respectively (used only on processors that support Intel 64 architecture)
* 
* Bits 3:0 tell us which control register is the subject of this exit:
* 
* 0 = CR0
* 3 = CR3
* 4 = CR4
* 8 = CR8
*/
STATIC
VOID
DispatchExitReasonControlRegisterAccess(
        _In_ PGUEST_CONTEXT Context
)
{
        MOV_CR_QUALIFICATION qualification = { 0 };

        qualification.All = VmcsReadExitQualification();

        switch (qualification.Fields.AccessType)
        {
        case TYPE_MOV_TO_CR: { DispatchExitReasonMovToCr(&qualification, Context); break; }
        case TYPE_MOV_FROM_CR: { DispatchExitReasonMovFromCr(&qualification, Context); break; }
        case TYPE_CLTS: { DEBUG_LOG("CLTS instruction"); break; }
        case TYPE_LMSW: { DEBUG_LOG("LMSW instruction"); break; }
        default: { break; }
        }
}

STATIC
VOID
DispatchExitReasonINVD(
        _In_ PGUEST_CONTEXT GuestState
)
{
        /* this is how hyper-v performs their invd */
        __wbinvd();
}

STATIC
VOID
DispatchExitReasonCPUID(
        _In_ PGUEST_CONTEXT GuestState
)
{

        PVIRTUAL_MACHINE_STATE state = &vmm_state[KeGetCurrentProcessorNumber()];

        /*
        * If its the first time performing the CPUID instruction from root mode, perform the
        * instruction and store the result in state->cache.cpuid.value. Then assign the result
        * to the designated registers. Once we have the result cached, set the active flag to true
        * to ensure all future CPUID vm exits simply retrieve the cached result.
        * 
        * Due to the frequent access to our VMM state structure, it should always remain cached. 
        * 
        * TODO: ensure each cache entry is word size aligned.
        */
        if (InterlockedExchange(&state->cache.cpuid.active, TRUE))
        {
                GuestState->rax = state->cache.cpuid.value[0];
                GuestState->rbx = state->cache.cpuid.value[1];
                GuestState->rcx = state->cache.cpuid.value[2];
                GuestState->rdx = state->cache.cpuid.value[3];
        }
        else
        {
                __cpuidex(state->cache.cpuid.value, (INT32)GuestState->rax, (INT32)GuestState->rcx);

                GuestState->rax = state->cache.cpuid.value[0];
                GuestState->rbx = state->cache.cpuid.value[1];
                GuestState->rcx = state->cache.cpuid.value[2];
                GuestState->rdx = state->cache.cpuid.value[3];

                InterlockedExchange(&state->cache.cpuid.active, TRUE);
        }
}

STATIC
VOID
DispatchExitReasonWBINVD(
        _In_ PGUEST_CONTEXT Context
)
{
        __wbinvd();
}

VOID
VmExitDispatcher(
        _In_ PGUEST_CONTEXT Context
)
{
        UINT64 additional_rip_offset = 0;

        switch (VmcsReadExitReason())
        {
        case EXIT_REASON_CPUID: { DispatchExitReasonCPUID(Context); break; }
        case EXIT_REASON_INVD: { DispatchExitReasonINVD(Context); break; }
        case EXIT_REASON_VMCALL:
        case EXIT_REASON_CR_ACCESS: { DispatchExitReasonControlRegisterAccess(Context); break; }
        case EXIT_REASON_WBINVD: { DispatchExitReasonWBINVD(Context); break; }
        case EXIT_REASON_EPT_VIOLATION:
        default: { break; }
        }

        /*
        * Once we have processed the initial instruction causing the vmexit, we can
        * translate the next instruction. Once decoded, if its a vm-exit causing instruction
        * we can process that instruction and then advance the rip by the size of the 2
        * exit-inducing instructions - saving us 1 vm exit (2 minus 1 = 1).
        */

#pragma warning(push)
#pragma warning(disable:6387)

        HandleFutureInstructions(
                (PVOID)(VmcsReadExitInstructionRip() + VmcsReadInstructionLength()),
                Context,
                &additional_rip_offset
        );

#pragma warning(pop)

        ResumeToNextInstruction(additional_rip_offset);
}

#define VMCALL_TERMINATE_VMX 0

VOID
DispatchVmCallTerminateVmx()
{
        UINT32 processor_index = 0;
        UINT64 guest_rsp = 0;
        UINT64 guest_rip = 0;
        UINT64 guest_cr3 = 0;
        UINT64 exit_instruction_length = 0;

        processor_index = KeGetCurrentProcessorNumber();

        __vmx_vmread(GUEST_RIP, &guest_rip);
        __vmx_vmread(GUEST_RSP, &guest_rsp);

        __vmx_vmread(GUEST_CR3, &guest_cr3);
        __writecr3(guest_cr3);

        __vmx_vmread(VM_EXIT_INSTRUCTION_LEN, &exit_instruction_length);

        guest_rip += exit_instruction_length;

        //vmm_state[processor_index].vm
}

VOID
VmCallDispatcher(
        _In_ UINT64 VmCallNumber,
        _In_ UINT64 OptionalParameter1,
        _In_ UINT64 OptionalParameter2,
        _In_ UINT64 OptionalParameter3
)
{
        switch (VmCallNumber)
        {
        case VMCALL_TERMINATE_VMX: { DispatchVmCallTerminateVmx(); break; }
        }
}