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
		if (Operands[1].reg.value == ZYDIS_REGISTER_RAX)
		{
			/*
			* Write the value from rax to cr3, we can then increment the rip
			* by 2 instructions saving a vm exit.
			*/
			DEBUG_LOG("Moving rax to cr3");
			__writecr3(GuestState->rax);
			return ZYAN_STATUS_SUCCESS;
		}
	}

	return ZYAN_STATUS_FAILED;
}

ZyanStatus
DecodeInstructionAtAddress(
	_In_ PVOID Address,
	_In_ ZydisDecodedInstruction* Instruction,
	_In_ ZydisDecodedOperand* Operands
)
{
	ZyanUSize size = 16;
	ZyanStatus status = ZYAN_STATUS_FAILED;
	ZydisDecoder decoder = { 0 };

	/*
	* For now, lets ignore usermode CPUID instructions
	*/
	if ((UINT64)Address <= 0xFFFF000000000000)
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
		Address,
		size,
		Instruction,
		Operands
	);

	if (!ZYAN_SUCCESS(status))
		return status;

	//DEBUG_LOG("Instruction: %x, length: %x", Instruction->mnemonic, Instruction->length);

	return status;
}