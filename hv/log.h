#ifndef LOG_H
#define LOG_H

#include "common.h"

#include "vmx.h"

#ifdef DEBUG
#        define HIGH_IRQL_LOG_SAFE(fmt, ...) \
                HvLogWrite("hv-root: " fmt, ##__VA_ARGS__)
#else
#        define HIGH_IRQL_LOG_SAFE(fmt, ...) 
#endif

NTSTATUS
HvLogInitialise(_In_ PVCPU Vcpu);

VOID
HvLogWrite(PCSTR Format, ...);

BOOLEAN
HvpLogCheckToFlush(_In_ PVCPU_LOG_STATE Logger);

VOID
HvLogCleanup(_In_ PVCPU Vcpu);

NTSTATUS
HvLogInitialisePreemptionTime(_In_ PVCPU Vcpu);

VOID
HvLogFlush(_In_ PVCPU_LOG_STATE Logger);

#endif