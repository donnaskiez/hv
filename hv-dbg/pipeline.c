#include "pipeline.h"

#include <intrin.h>

ZyanStatus
CheckForExitingInstruction(
	_In_ ZydisDecodedInstruction* Instruction,
	_In_ ZydisDecodedOperand* Operands,
	_In_ PGUEST_REGS GuestState
)
{
	if (Operands[0].reg.value == ZYDIS_REGISTER_CR3)
	{
		//DEBUG_LOG("operand 2: %x", (ULONG)Operands[1].reg.value);

		if (Operands[1].reg.value == ZYDIS_REGISTER_RAX)
		{
			/*
			* Here we write the lower 16 bits of r14 to cr3
			*/

			DEBUG_LOG("Writing to cr3 from rax");
			__writecr3(GuestState->rax);
			return ZYAN_STATUS_SUCCESS;
		}
	}

	return ZYAN_STATUS_FALSE;
}

ZyanStatus
TranslateNextInstruction(
	_In_ PVOID Instruction,
	_In_ PGUEST_REGS GuestState,
	_Out_ PUINT64 NextInstructionLength
)
{
	ZyanUSize size = 16;
	ZyanStatus status = ZYAN_STATUS_FAILED;
	ZydisDecoder decoder = { 0 };
	ZydisDecodedInstruction instruction = { 0 };
	ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT] = { 0 };
	
	*NextInstructionLength = 0;

	if ((UINT64)Instruction <= 0xFFFF000000000000)
		return ZYAN_STATUS_SUCCESS;

	status = ZydisDecoderInit(
		&decoder,
		ZYDIS_MACHINE_MODE_LONG_64,
		ZYDIS_STACK_WIDTH_64
	);

	if (!ZYAN_SUCCESS(status))
		return status;

	status = ZydisDecoderDecodeFull(
		&decoder,
		Instruction,
		size,
		&instruction,
		operands
	);

	if (!ZYAN_SUCCESS(status))
		return status;

	status = CheckForExitingInstruction(&instruction, operands, GuestState);

	if (!ZYAN_SUCCESS(status))
		return ZYAN_STATUS_FAILED;

	*NextInstructionLength = instruction.length;

	return status;
}