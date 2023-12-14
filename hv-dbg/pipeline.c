#include "pipeline.h"

#include <intrin.h>

/*
 * This is a custom implementation of a paper published by some vmware
 * engineers which can be seen here:
 *
 * https://www.usenix.org/system/files/conference/atc12/atc12-final158.pdf
 *
 * Right now it produces around a 3-5% performance increase depending on the
 * instructions in the cluster (and my clusters are only 2 instructions as of
 * now) but I think its still a cool start and was fun building. (besides
 * implementing Zydis... Thankyou matti for that...)
 */

/*
 * Once initialised the decoder is constant and not changed, so we can use
 * a single instance for every core.
 */
ZydisDecoder decoder = {0};

ZyanStatus
InitialiseDisassemblerState()
{
        return ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
}

/*
 * Lets take the following instruction as an example:
 *
 *	mov cr3, rax
 *
 * The Instruction is the "mov", the first operand is cr3, and the second
 * operand in rax. The Operands argument is an array of operands from left
 * to right given an instruction.
 */
STATIC
ZyanStatus
DispatchMovInstruction(_In_ ZydisDecodedOperand* Operands, _In_ PGUEST_CONTEXT Context)
{
        switch (Operands[0].reg.value)
        {
        case ZYDIS_REGISTER_CR3:
        {
                switch (Operands[1].reg.value)
                {
                case ZYDIS_REGISTER_RAX:
                {
                        __writecr3(Context->rax);
                        return ZYAN_STATUS_SUCCESS;
                }
                default:
                {
                        return ZYAN_STATUS_FAILED;
                }
                }
        }
        case ZYDIS_REGISTER_CR4:
        {
                switch (Operands[1].reg.value)
                {
                case ZYDIS_REGISTER_RAX:
                {
                        __writecr4(Context->rax);
                        return ZYAN_STATUS_SUCCESS;
                }
                default:
                {
                        return ZYAN_STATUS_FAILED;
                }
                }
        }
        case ZYDIS_REGISTER_CR0:
        {
                switch (Operands[1].reg.value)
                {
                case ZYDIS_REGISTER_RAX:
                {
                        __writecr0(Context->rax);
                        return ZYAN_STATUS_SUCCESS;
                }
                default:
                {
                        return ZYAN_STATUS_FAILED;
                }
                }
        }
        case ZYDIS_REGISTER_RAX:
        {
                switch (Operands[1].reg.value)
                {
                case ZYDIS_REGISTER_CR3:
                {
                        Context->rax = __readcr3();
                        return ZYAN_STATUS_SUCCESS;
                }
                case ZYDIS_REGISTER_CR4:
                {
                        Context->rax = __readcr4();
                        return ZYAN_STATUS_SUCCESS;
                }
                case ZYDIS_REGISTER_CR0:
                {
                        Context->rax = __readcr0();
                        return ZYAN_STATUS_SUCCESS;
                }
                default:
                {
                        return ZYAN_STATUS_FAILED;
                }
                }
        }
        default:
        {
                return ZYAN_STATUS_FAILED;
        }
        }
}

ZyanStatus
CheckForExitingInstruction(_In_ ZydisDecodedInstruction* Instruction,
                           _In_ ZydisDecodedOperand*     Operands,
                           _In_ PGUEST_CONTEXT           GuestState)
{
        switch (Instruction->mnemonic)
        {
        case ZYDIS_MNEMONIC_CPUID:
        {
                DEBUG_LOG("next instruction CPUID");
                return ZYAN_STATUS_FAILED;
        }
        case ZYDIS_MNEMONIC_MOV:
        {
                DEBUG_LOG("Next instruction MOV");
                return DispatchMovInstruction(Operands, GuestState);
        }

                /*
                 * Since we simply passthrough any RDMSR / WRMSR instructions we
                 * can simply return success which will increment the rip by the
                 * size of the respective instruction.
                 */
        case ZYDIS_MNEMONIC_RDMSR:
        {
                DEBUG_LOG("Next instruction RDMSR");
                return ZYAN_STATUS_SUCCESS;
        }
        case ZYDIS_MNEMONIC_WRMSR:
        {
                DEBUG_LOG("Next instruction WRMSR");
                return ZYAN_STATUS_SUCCESS;
        }
        case ZYDIS_MNEMONIC_INVD:
        {
                DEBUG_LOG("Next instruction INVD");
                __wbinvd();
                return ZYAN_STATUS_SUCCESS;
        }
        case ZYDIS_MNEMONIC_WBINVD:
        {
                DEBUG_LOG("Next instruction WBINVD");
                __wbinvd();
                return ZYAN_STATUS_SUCCESS;
        }
        }

        return ZYAN_STATUS_FAILED;
}

ZyanStatus
DecodeInstructionAtAddress(_In_ PVOID                    Address,
                           _In_ ZydisDecodedInstruction* Instruction,
                           _In_ ZydisDecodedOperand*     Operands)
{
        ZyanUSize  size   = 16;
        ZyanStatus status = ZYAN_STATUS_FAILED;

        /*
         * For now, lets ignore usermode CPUID instructions
         */
        if ((UINT64)Address <= 0xFFFF000000000000)
                return ZYAN_STATUS_FAILED;

        return ZydisDecoderDecodeFull(&decoder, Address, size, Instruction, Operands);
}

ZyanStatus
HandleFutureInstructions(_In_ PVOID             NextInstruction,
                         _Inout_ PGUEST_CONTEXT Context,
                         _Out_ PUINT64          RipIncrementSize)
{
        ZyanStatus              status                            = ZYAN_STATUS_FAILED;
        ZydisDecodedOperand     operands[ZYDIS_MAX_OPERAND_COUNT] = {0};
        ZydisDecodedInstruction instruction                       = {0};

        *RipIncrementSize = 0;

        status = DecodeInstructionAtAddress(NextInstruction, &instruction, operands);

        if (!ZYAN_SUCCESS(status))
                return status;

        status = CheckForExitingInstruction(&instruction, operands, Context);

        if (!ZYAN_SUCCESS(status))
                return status;

        *RipIncrementSize = instruction.length;

        return status;
}
