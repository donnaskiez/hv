#ifndef LOG_H
#define LOG_H

#include "common.h"
#include "vmx.h"
#include "log_config.h"

// Enhanced logging macros with levels and categories
#ifdef DEBUG
#define HV_LOG_DEBUG(category, fmt, ...) \
    HvLogWrite(LOG_LEVEL_DEBUG, category, fmt, ##__VA_ARGS__)
#define HV_LOG_INFO(category, fmt, ...) \
    HvLogWrite(LOG_LEVEL_INFO, category, fmt, ##__VA_ARGS__)
#define HV_LOG_WARNING(category, fmt, ...) \
    HvLogWrite(LOG_LEVEL_WARNING, category, fmt, ##__VA_ARGS__)
#define HV_LOG_ERROR(category, fmt, ...) \
    HvLogWrite(LOG_LEVEL_ERROR, category, fmt, ##__VA_ARGS__)
#define HV_LOG_CRITICAL(category, fmt, ...) \
    HvLogWrite(LOG_LEVEL_CRITICAL, category, fmt, ##__VA_ARGS__)
#define HIGH_IRQL_LOG_SAFE(fmt, ...) \
    HvLogWrite(LOG_LEVEL_DEBUG, LOG_CATEGORY_GENERAL, "hv-root: " fmt, ##__VA_ARGS__)
#else
#define HV_LOG_DEBUG(category, fmt, ...)
#define HV_LOG_INFO(category, fmt, ...)
#define HV_LOG_WARNING(category, fmt, ...)
#define HV_LOG_ERROR(category, fmt, ...)
#define HV_LOG_CRITICAL(category, fmt, ...)
#define HIGH_IRQL_LOG_SAFE(fmt, ...)
#endif

// Core logging functions
NTSTATUS HvLogInitialise(_In_ PVCPU Vcpu);
VOID HvLogWrite(_In_ LOG_LEVEL Level, _In_ LOG_CATEGORY Category, _In_ PCSTR Format, ...);
BOOLEAN HvpLogCheckToFlush(_In_ PVCPU_LOG_STATE Logger);
VOID HvLogCleanup(_In_ PVCPU Vcpu);
NTSTATUS HvLogInitialisePreemptionTime(_In_ PVCPU Vcpu);
VOID HvLogFlush(_In_ PVCPU_LOG_STATE Logger);

// Performance monitoring functions
VOID HvLogPerformanceStart(_In_ PVCPU Vcpu, _In_ PCSTR Operation);
VOID HvLogPerformanceEnd(_In_ PVCPU Vcpu, _In_ PCSTR Operation);

#endif