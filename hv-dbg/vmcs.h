#ifndef VMCS_H
#define VMCS_H

#include "common.h"
#include "vmx.h"

NTSTATUS
SetupVmcs(
        _In_ PVIRTUAL_MACHINE_STATE GuestState,
        _In_ PVOID StackPointer
);

#endif