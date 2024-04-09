#ifndef EXIT_H
#define EXIT_H

#include "common.h"

#include "vmx.h"

BOOLEAN
VmExitDispatcher(_In_ PGUEST_CONTEXT GuestState);

VOID
LoadHostDebugRegisterState();

VOID
StoreHostDebugRegisterState();

#endif