#include "pipeline.h"

ZyanStatus
TranslateNextInstruction(
	_In_ PVOID Instruction
)
{
	ZyanUSize size = 16;
	ZyanStatus status = ZYAN_STATUS_FAILED;
	ZydisDecoder decoder = { 0 };
	ZydisDecodedInstruction instruction = { 0 };
	ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT] = { 0 };

	status = ZydisDecoderInit(
		&decoder,
		ZYDIS_MACHINE_MODE_LONG_64,
		ZYDIS_STACK_WIDTH_64
	);

	if (!ZYAN_SUCCESS(status))
	{
		DEBUG_ERROR("ZydisDecoderInit failed with status %x", status);
		return status;
	}
	
	status = ZydisDecoderDecodeFull(
		&decoder,
		Instruction,
		size,
		&instruction,
		operands
	);

	if (!ZYAN_SUCCESS(status))
	{
		DEBUG_ERROR("ZydisDecoderDecodeBuffer failed with status %x", status);
		return status;
	}

	if (instruction.mnemonic == ZYDIS_MNEMONIC_CPUID)
	{
		DEBUG_LOG("Next instruction is CPUid!");
	}

	DEBUG_LOG("Length: %lx, Opcode: %lx", (ULONG)instruction.length, (ULONG)instruction.opcode);

	return status;
}