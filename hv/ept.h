#ifndef EPT_H
#define EPT_H

#include <ntddk.h>

#include "ia32.h"

NTSTATUS
InitializeEptp(_Out_ EPT_POINTER** EptPointer);

#endif