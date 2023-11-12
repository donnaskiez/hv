#ifndef PIPELINE_H
#define PIPELINE_H

#include "common.h"

#include <Zydis/Zydis.h>

ZyanStatus
DecodeInstructionAtAddress(
	_In_ PVOID Address,
	_In_ ZydisDecodedInstruction* Instruction,
	_In_ ZydisDecodedOperand* Operand
);

ZyanStatus
CheckForExitingInstruction(
	_In_ ZydisDecodedInstruction* Instruction,
	_In_ ZydisDecodedOperand* Operands,
	_In_ PGUEST_REGS GuestState
);

#endif