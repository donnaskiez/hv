#ifndef LOG_CONFIG_H
#define LOG_CONFIG_H

#include "common.h"

// Log levels for different types of messages
typedef enum _LOG_LEVEL {
    LOG_LEVEL_DEBUG = 0,
    LOG_LEVEL_INFO,
    LOG_LEVEL_WARNING,
    LOG_LEVEL_ERROR,
    LOG_LEVEL_CRITICAL
} LOG_LEVEL;

// Log categories for better organization
typedef enum _LOG_CATEGORY {
    LOG_CATEGORY_GENERAL = 0,
    LOG_CATEGORY_VMX,
    LOG_CATEGORY_VMCS,
    LOG_CATEGORY_HYPERCALL,
    LOG_CATEGORY_PERFORMANCE,
    LOG_CATEGORY_SECURITY
} LOG_CATEGORY;

// Configuration structure for logging
typedef struct _LOG_CONFIG {
    LOG_LEVEL min_level;           // Minimum level to log
    BOOLEAN enable_timestamps;     // Include timestamps in logs
    BOOLEAN enable_categories;     // Include categories in logs
    BOOLEAN enable_cpu_info;       // Include CPU/VCPU info
    UINT32 buffer_flush_threshold; // Percentage threshold to trigger flush (0-100)
    UINT32 max_message_length;     // Maximum length of a single log message
} LOG_CONFIG, *PLOG_CONFIG;

// Default configuration values
#define LOG_DEFAULT_MIN_LEVEL           LOG_LEVEL_INFO
#define LOG_DEFAULT_ENABLE_TIMESTAMPS   TRUE
#define LOG_DEFAULT_ENABLE_CATEGORIES   TRUE
#define LOG_DEFAULT_ENABLE_CPU_INFO     TRUE
#define LOG_DEFAULT_FLUSH_THRESHOLD     50    // 50% buffer usage triggers flush
#define LOG_DEFAULT_MAX_MESSAGE_LENGTH  512   // bytes

// Log format strings
#define LOG_FORMAT_WITH_ALL      "[%s][CPU:%d][VCPU:%d][%s] %s"
#define LOG_FORMAT_NO_CATEGORY   "[%s][CPU:%d][VCPU:%d] %s"
#define LOG_FORMAT_BASIC         "[%s] %s"

// Function declarations
NTSTATUS HvLogConfigInitialize(_Out_ PLOG_CONFIG Config);
VOID HvLogConfigSetLevel(_Inout_ PLOG_CONFIG Config, _In_ LOG_LEVEL Level);
BOOLEAN HvLogShouldLog(_In_ PLOG_CONFIG Config, _In_ LOG_LEVEL Level);

#endif // LOG_CONFIG_H