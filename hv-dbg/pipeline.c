#include "pipeline.h"

#include <intrin.h>

//typedef struct _DISASSEMBLER_STATE
//{
//	ZydisDecoder decoder;
//}
//DISASSEMBLER_STATE, *PDISASSEMBLER_STATE;
//
//PDISASSEMBLER_STATE state = NULL;
//
//ZyanStatus
//InitialiseDisassemblerState()
//{
//	DEBUG_LOG("Initialise disassembler state");
//
//	ZyanStatus status = ZYAN_STATUS_FAILED;
//
//	state = ExAllocatePool2(POOL_FLAG_NON_PAGED, 
//		KeQueryActiveProcessorCount(0) * sizeof(DISASSEMBLER_STATE), POOL_TAG_VMM);
//
//	if (!state)
//		return ZYAN_STATUS_NOT_ENOUGH_MEMORY;
//
//	status = ZydisDecoderInit(
//		&state[KeGetCurrentProcessorNumber()].decoder,
//		ZYDIS_MACHINE_MODE_LONG_64,
//		ZYDIS_STACK_WIDTH_64
//	);
//
//	if (!ZYAN_SUCCESS(status))
//	{
//		DEBUG_ERROR("ZydisDecoderInit failed with status %x", status);
//		return status;
//	}
//
//	return status;
//}
//
///*
//* Lets take the following instruction as an example:
//* 
//*	mov cr3, rax
//* 
//* The Instruction is the "mov", the first operand is cr3, and the second
//* operand in rax. The Operands argument is an array of operands from left
//* to right given an instruction.
//*/
//STATIC
//ZyanStatus
//DispatchMovInstruction(
//	_In_ ZydisDecodedOperand* Operands,
//	_In_ PGUEST_REGS GuestState
//)
//{
//	//switch (Operands[0].reg.value)
//	//{
//	//case ZYDIS_REGISTER_CR3:
//	//{
//	//	switch (Operands[1].reg.value)
//	//	{
//	//	case ZYDIS_REGISTER_RAX:
//	//		DEBUG_LOG("Writing to rax");
//	//		__writecr3(GuestState->rax);
//	//		return ZYAN_STATUS_SUCCESS;
//	//	}
//	//}
//	//case ZYDIS_REGISTER_CR4:
//	//case ZYDIS_REGISTER_CR0:;
//	//}
//
//	if (Operands[0].reg.value == ZYDIS_REGISTER_CR3)
//	{
//		if (Operands[1].reg.value == ZYDIS_REGISTER_RAX)
//		{
//			/*
//			* Write the value from rax to cr3, we can then increment the rip
//			* by 2 instructions saving a vm exit.
//			*/
//			DEBUG_LOG("Moving rax to cr3");
//			__writecr3(GuestState->rax);
//			return ZYAN_STATUS_SUCCESS;
//		}
//	}
//
//	return ZYAN_STATUS_FAILED;
//}
//
//ZyanStatus
//CheckForExitingInstruction(
//	_In_ PGUEST_REGS GuestState,
//	_In_ ZydisDecodedOperand* Operands,
//	_In_ ZydisDecodedInstruction* Instruction
//)
//{
//	switch (Instruction->mnemonic)
//	{
//	//case ZYDIS_MNEMONIC_CPUID:
//	case ZYDIS_MNEMONIC_MOV: { return DispatchMovInstruction(Operands, GuestState); }
//	//case ZYDIS_MNEMONIC_RDMSR: { return ZYAN_STATUS_SUCCESS; }
//	//case ZYDIS_MNEMONIC_WRMSR: { return ZYAN_STATUS_SUCCESS; }
//	//case ZYDIS_MNEMONIC_INVD: { __wbinvd(); return ZYAN_STATUS_SUCCESS; }
//	}
//
//	return ZYAN_STATUS_FAILED;
//}
//
//STATIC
//ZyanStatus
//DecodeInstructionAtAddress(
//	_In_ PVOID Address,
//	_In_ ZydisDecodedOperand* Operands,
//	_In_ ZydisDecodedInstruction* Instruction,
//	_In_ ZydisDecoder* Decoder
//)
//{
//	ZyanUSize size = 16;
//	ULONG proc_num = KeGetCurrentProcessorNumber();
//	/*
//	* For now, lets ignore usermode CPUID instructions
//	*/
//	if ((UINT64)Address <= 0xFFFF000000000000)
//		return ZYAN_STATUS_SUCCESS;
//
//	return ZydisDecoderDecodeFull(
//		Decoder,
//		Address,
//		size,
//		Instruction,
//		Operands
//	);
//}
//

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
		return ZYAN_STATUS_FAILED;

	status = ZydisDecoderInit(
		&decoder,
		ZYDIS_MACHINE_MODE_LONG_64,
		ZYDIS_STACK_WIDTH_64
	);

	if (!ZYAN_SUCCESS(status))
		return status;

	return ZydisDecoderDecodeFull(
		&decoder,
		Address,
		size,
		Instruction,
		Operands
	);
}

ZyanStatus
HandleFutureInstructions(
	_In_ PVOID NextInstruction,
	_Inout_ PGUEST_REGS GuestState,
	_Out_ PUINT64 RipIncrementSize
)
{
	ZyanStatus status = ZYAN_STATUS_FAILED;
	ZydisDecoder decoder = { 0 };
	ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT] = { 0 };
	ZydisDecodedInstruction instruction = { 0 };

	*RipIncrementSize = 0;

	status = DecodeInstructionAtAddress(
		NextInstruction, 
		&instruction, 
		operands
	);

	if (!ZYAN_SUCCESS(status))
		return status;

	status = CheckForExitingInstruction(
		&instruction,
		operands,
		GuestState
	);

	if (!ZYAN_SUCCESS(status))
		return status;

	*RipIncrementSize = instruction.length;

	return status;
}
