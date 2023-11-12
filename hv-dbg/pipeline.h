#ifndef PIPELINE_H
#define PIPELINE_H

#include "common.h"

#include <Zydis/Zydis.h>

ZyanStatus
TranslateNextInstruction(
	_In_ PVOID Instruction
);

#endif