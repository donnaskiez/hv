#ifndef PIPELINE_H
#define PIPELINE_H

#include "common.h"

#include <Zydis/Zydis.h>

ZyanStatus
TranslateNextInstruction(
	_In_ PVOID Instruction,
	_In_ PGUEST_REGS GuestState,
	_Out_ PUINT64 NextInstructionLength
);

#endif