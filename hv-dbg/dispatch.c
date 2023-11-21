#include "dispatch.h"

#include "Zydis/Zydis.h"
#include "vmx.h"
#include "pipeline.h"

VOID
ResumeToNextInstruction(
        _In_ UINT64 InstructionOffset
)
{
        PVOID current_rip = NULL;
        ULONG exit_instruction_length = 0;

        /*
        * Advance the guest RIP by the size of the exit-causing instruction
        */
        __vmx_vmread(GUEST_RIP, &current_rip);
        __vmx_vmread(VM_EXIT_INSTRUCTION_LEN, &exit_instruction_length);
        __vmx_vmwrite(GUEST_RIP, (UINT64)current_rip + exit_instruction_length + InstructionOffset);
}

VOID
VmResumeInstruction()
{
        __vmx_vmresume();

        /* If vmresume succeeds we won't reach here */

        UINT64 error = 0;

        __vmx_vmread(VM_INSTRUCTION_ERROR, &error);
        __vmx_off();

        DEBUG_ERROR("VMRESUME Error : 0x%llx", error);
}

STATIC
VOID
DispatchExitReasonControlRegisterAccess(
        _In_ PGUEST_CONTEXT Context
)
{
        INT64 rsp = 0;
        ULONG exit_qualification = 0;

        __vmx_vmread(EXIT_QUALIFICATION, &exit_qualification);

        PMOV_CR_QUALIFICATION data = (PMOV_CR_QUALIFICATION)&exit_qualification;
        PUINT64 register_ptr = (PUINT64)&Context->rax + data->Fields.Register;

        if (data->Fields.Register == 4)
        {
                __vmx_vmread(GUEST_RSP, &rsp);
                *register_ptr = rsp;
        }

        switch (data->Fields.AccessType)
        {
        case TYPE_MOV_TO_CR:
        {
                switch (data->Fields.ControlRegister)
                {
                case 0:
                        __vmx_vmwrite(GUEST_CR0, *register_ptr);
                        __vmx_vmwrite(CR0_READ_SHADOW, *register_ptr);
                        break;
                case 3:
                        __vmx_vmwrite(GUEST_CR3, (*register_ptr & ~(1ULL << 63)));
                        break;
                case 4:
                        __vmx_vmwrite(GUEST_CR4, *register_ptr);
                        __vmx_vmwrite(CR4_READ_SHADOW, *register_ptr);
                        break;
                default:
                        DEBUG_LOG("Register not supported.");
                        break;
                }
        }
        break;

        case TYPE_MOV_FROM_CR:
        {
                switch (data->Fields.ControlRegister)
                {
                case 0:
                        __vmx_vmread(GUEST_CR0, register_ptr);
                        break;
                case 3:
                        __vmx_vmread(GUEST_CR3, register_ptr);
                        break;
                case 4:
                        __vmx_vmread(GUEST_CR4, register_ptr);
                        break;
                default:
                        DEBUG_LOG("Register not supported.");
                        break;
                }
        }
        break;

        default:
                break;
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
        INT32 cpuid_result[4];

        __cpuidex(cpuid_result, (INT32)GuestState->rax, (INT32)GuestState->rcx);

        GuestState->rax = cpuid_result[0];
        GuestState->rbx = cpuid_result[1];
        GuestState->rcx = cpuid_result[2];
        GuestState->rdx = cpuid_result[3];
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
        ULONG exit_reason = 0;
        ULONG exit_qualification = 0;
        UINT64 current_rip = 0;
        ULONG exit_instruction_length = 0;
        UINT64 increment_size = 0;
        ZyanStatus status = ZYAN_STATUS_ACCESS_DENIED;

        __vmx_vmread(VM_EXIT_REASON, &exit_reason);
        __vmx_vmread(EXIT_QUALIFICATION, &exit_qualification);
        __vmx_vmread(GUEST_RIP, &current_rip);
        __vmx_vmread(VM_EXIT_INSTRUCTION_LEN, &exit_instruction_length);

        switch (exit_reason)
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

        status = HandleFutureInstructions(
                (PVOID)(current_rip + exit_instruction_length),
                Context,
                &additional_rip_offset
        );

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