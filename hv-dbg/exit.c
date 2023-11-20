#include "exit.h"

#include "ia32.h"
#include "Zydis/Zydis.h"

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

        PMOV_CR_QUALIFICATION qual = (PMOV_CR_QUALIFICATION)&exit_qualification;
        PUINT64 register_ptr = (PUINT64)&Context->rax + qual->Fields.Register;

        if (qual->Fields.Register == 4)
        {
                __vmx_vmread(GUEST_RSP, &rsp);
                *register_ptr = rsp;
        }

        switch (qual->Fields.AccessType)
        {
        case TYPE_MOV_TO_CR:
        {
                switch (qual->Fields.ControlRegister)
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
                switch (qual->Fields.ControlRegister)
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
        _In_ PGUEST_CONTEXT Context
)
{
        /* this is how hyper-v performs their invd */
        __wbinvd();
}

STATIC
VOID
DispatchExitReasonWBINVD(
        _In_ PGUEST_CONTEXT Context
)
{
        __wbinvd();
}

STATIC
VOID
DispatchExitReasonCPUID(
        _In_ PGUEST_CONTEXT Context
)
{
        INT32 cpuid_result[4];

        __cpuidex(cpuid_result, (INT32)Context->rax, (INT32)Context->rcx);

        Context->rax = cpuid_result[0];
        Context->rbx = cpuid_result[1];
        Context->rcx = cpuid_result[2];
        Context->rdx = cpuid_result[3];
}

/*
* Reads the current value of the processor’s time-stamp counter (a 64-bit MSR) 
* into the EDX:EAX registers. The EDX register is loaded with the high-order 
* 32 bits of the MSR and the EAX register is loaded with the low-order 32 bits. 
* (On processors that support the Intel 64 architecture, the high-order 32 bits 
* of each of RAX and RDX are cleared.)
* 
* source: https://www.felixcloutier.com/x86/rdtsc
*/
STATIC
VOID
DispatchExitReasonRDTSC(
        _In_ PGUEST_CONTEXT Context
)
{
        DEBUG_LOG("rdtsc exit");

        LARGE_INTEGER tsc = { 0 };
        tsc.QuadPart = __rdtsc();

        Context->rax = 0;
        Context->rdx = 0;

        Context->rax = tsc.LowPart;
        Context->rdx = tsc.HighPart;
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
        case EXIT_REASON_VMCLEAR:
        case EXIT_REASON_VMPTRLD:
        case EXIT_REASON_VMPTRST:
        case EXIT_REASON_VMREAD:
        case EXIT_REASON_VMRESUME:
        case EXIT_REASON_VMWRITE:
        case EXIT_REASON_VMXOFF:
        case EXIT_REASON_VMXON:
        case EXIT_REASON_VMLAUNCH:
        case EXIT_REASON_HLT:
        case EXIT_REASON_RDTSC: { DispatchExitReasonRDTSC(Context); break; }
        case EXIT_REASON_EXCEPTION_NMI:
        case EXIT_REASON_CPUID: { DispatchExitReasonCPUID(Context); break; }
        case EXIT_REASON_INVD: { DispatchExitReasonINVD(Context); break; }
        case EXIT_REASON_VMCALL:
        case EXIT_REASON_CR_ACCESS: { DispatchExitReasonControlRegisterAccess(Context); break; }
        case EXIT_REASON_MSR_READ:
        case EXIT_REASON_MSR_WRITE:
        case EXIT_REASON_EPT_VIOLATION:
        case EXIT_REASON_WBINVD: { DispatchExitReasonWBINVD(Context); break; }
        default: { break; }
        }

        /*
        * Once we have processed the initial instruction causing the vmexit, we can
        * translate the next instruction. Once decoded, if its a vm-exit causing instruction
        * we can process that instruction and then advance the rip by the size of the 2
        * exit-inducing instructions - saving us 1 vm exit (2 minus 1 = 1).
        */

        //status = HandleFutureInstructions(
        //        (PVOID)(current_rip + exit_instruction_length),
        //        GuestState,
        //        &additional_rip_offset
        //);

        ResumeToNextInstruction(0);
}
