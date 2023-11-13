#ifndef PIPELINE_H
#define PIPELINE_H

#include "common.h"

#include <Zydis/Zydis.h>

ZyanStatus
HandleFutureInstructions(
	_In_ PVOID NextInstruction,
	_Inout_ PGUEST_REGS GuestState,
	_Out_ PUINT64 RipIncrementSize
);

ZyanStatus
InitialiseDisassemblerState();

#endif