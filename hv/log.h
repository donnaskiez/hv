#ifndef LOG_H
#define LOG_H

#include "common.h"

#include "vmx.h"

#ifdef DEBUG
#        define HIGH_IRQL_LOG_SAFE(fmt, ...) \
                LogToBuffer("hv-root: " fmt, ##__VA_ARGS__)
#else
#        define HIGH_IRQL_LOG_SAFE(fmt, ...)
#endif

NTSTATUS
InitialiseVcpuLogger(_In_ PVIRTUAL_MACHINE_STATE Vcpu);

VOID
LogToBuffer(PCSTR Format, ...);

BOOLEAN
CheckToFlushLogs(_In_ PVIRTUAL_MACHINE_STATE Vcpu);

VOID
CleanupLoggerOnUnload(_In_ PVIRTUAL_MACHINE_STATE Vcpu);

#endif