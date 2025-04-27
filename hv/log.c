#include "log.h"

#include "common.h"
#include "arch.h"
#include "vmcs.h"
#include "log_config.h"

#include <ntstrsafe.h>
#include <stdarg.h>

// Global logging configuration
STATIC LOG_CONFIG g_LogConfig = {
    .min_level = LOG_DEFAULT_MIN_LEVEL,
    .enable_timestamps = LOG_DEFAULT_ENABLE_TIMESTAMPS,
    .enable_categories = LOG_DEFAULT_ENABLE_CATEGORIES,
    .enable_cpu_info = LOG_DEFAULT_ENABLE_CPU_INFO,
    .buffer_flush_threshold = LOG_DEFAULT_FLUSH_THRESHOLD,
    .max_message_length = LOG_DEFAULT_MAX_MESSAGE_LENGTH
};

// Performance monitoring structure
typedef struct _PERFORMANCE_MONITOR {
    UINT64 start_time;
    UINT64 total_time;
    UINT32 count;
    PCSTR operation;
} PERFORMANCE_MONITOR, *PPERFORMANCE_MONITOR;

#pragma warning(push)
#pragma warning(disable : 28182)

#define VMX_LOG_PREEMPTION_INTERVAL_MS 500

/* For when we are running in a vm */
#define VMX_LOG_PREEMPTION_TIME_FALLBACK 2

#if DEBUG

/* Right now its quite interesting, if this routine doesnt cause a vmexit the
 * logging should be fairly solid, however if this function causes a VM exit it
 * may be a problem... */
STATIC
VOID
HvpLogDpcFlushRoutine(
    _In_ PKDPC* Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2)
{
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    NT_ASSERT(DeferredContext != NULL);

    PVCPU_LOG_STATE logger = (PVCPU_LOG_STATE)DeferredContext;
    UINT32 head = 0;
    UINT32 tail = 0;
    UINT32 index = 0;
    PLOG_ENTRY entry = NULL;

    InterlockedIncrement(&logger->flushing);

    /* no need to check for valid context, assert used instead */
    head = logger->head;
    tail = logger->tail;

    while (tail < head) {
        index = tail % VMX_MAX_LOG_ENTRIES_COUNT;
        entry = &logger->logs[index];

        /* DPC runs on the same core, hence can defer work here */
        DEBUG_LOG_ROOT(
            "[CPU: %lu][VCPU: %llu] %s",
            KeGetCurrentProcessorNumber(),
            entry->timestamp,
            entry->message);

        tail++;
    }

    logger->tail = tail;
    InterlockedDecrement(&logger->flushing);
}

/* 500ms preemption intervals */
NTSTATUS
HvLogInitialisePreemptionTime(_In_ PVCPU Vcpu)
{
    UINT64 tsc_hz = 0;
    UINT8 tsc_shift = 0;
    UINT64 tsc_per_timer_tick = 0;
    UINT64 desired_tsc_ticks = 0;
    CPUID_EAX_15 cpuid_15 = {0};
    IA32_VMX_MISC_REGISTER misc = {.AsUInt = __readmsr(IA32_VMX_MISC)};

    __cpuidex(&cpuid_15, CPUID_TIME_STAMP_COUNTER_INFORMATION, 0);

    if (!cpuid_15.Eax.Denominator || !cpuid_15.Ebx.Numerator ||
        !cpuid_15.Ecx.NominalFrequency) {
        //Vcpu->preemption_time = VMX_LOG_PREEMPTION_TIME_FALLBACK;
        Vcpu->preemption_time = 0;
        return STATUS_SUCCESS;
    }

    tsc_hz = ((UINT64)cpuid_15.Ecx.NominalFrequency *
              (UINT64)cpuid_15.Ebx.Numerator) /
             (UINT64)cpuid_15.Eax.Denominator;

    tsc_shift = IA32_VMX_MISC_PREEMPTION_TIMER_TSC_RELATIONSHIP(misc.AsUInt);
    tsc_per_timer_tick = 1ull << tsc_shift;
    desired_tsc_ticks = (tsc_hz * VMX_LOG_PREEMPTION_INTERVAL_MS) / 1000ull;

    Vcpu->preemption_time =
        (UINT32)((desired_tsc_ticks + tsc_per_timer_tick - 1) /
                 tsc_per_timer_tick);

    return STATUS_SUCCESS;
}

VOID
HvLogCleanup(_In_ PVCPU Vcpu)
{
    DEBUG_LOG(
        "Vcpu: %lx - log count: %llx",
        KeGetCurrentProcessorNumber(),
        Vcpu->log_state.log_count);

    DEBUG_LOG(
        "Vcpu: %lx - flush miss count: %llx",
        KeGetCurrentProcessorNumber(),
        Vcpu->log_state.flush_miss_count);

    DEBUG_LOG(
        "Vcpu: %lx - discard count: %llx",
        KeGetCurrentProcessorNumber(),
        Vcpu->log_state.discard_count);
}

NTSTATUS
HvLogInitialise(_In_ PVCPU Vcpu)
{
    PVCPU_LOG_STATE state = &Vcpu->log_state;

    state->head = 0;
    state->tail = 0;
    state->log_count = 0;
    state->discard_count = 0;
    RtlZeroMemory(state->logs, sizeof(state->logs));

    KeInitializeDpc(&state->dpc, HvpLogDpcFlushRoutine, state);

    return STATUS_SUCCESS;
}

BOOLEAN
HvpLogCheckToFlush(_In_ PVCPU_LOG_STATE Logger)
{
    /* flush at 50% capacity */
    UINT32 usage = Logger->head - Logger->tail;
    UINT32 threshold = (UINT32)((VMX_MAX_LOG_ENTRIES_COUNT * 50) / 100);
    return (usage >= threshold) ? TRUE : FALSE;
}

VOID
HvLogFlush(_In_ PVCPU_LOG_STATE Logger)
{
    KeInsertQueueDpc(&Logger->dpc, NULL, NULL);
}

/*
 * Since I can't be bothered to write my own "safe" implementation of vsprintf,
 * I am opting to use RtlStringCbVPrintfA. Now RtlStringCbVPrintfA according to
 * the documentation can only be run at IRQL = PASSIVE_LEVEL. However, DbgPrint
 * can be used at IRQL <= DIRQL and I am assuming it uses RtlStringCbVPrintfA to
 * convert the variadic arguments into the final string to be logged. However,
 * this is only true for non wide string arguments. Now I am not sure why this
 * can't be used at HIGH_LEVEL but I am risking it since this is not a
 * production ready project anyway and more for just fun and learning purposes.
 */
VOID
HvLogWrite(_In_ LOG_LEVEL Level, _In_ LOG_CATEGORY Category, _In_ PCSTR Format, ...)
{
    NTSTATUS status = STATUS_SUCCESS;
    PVCPU vcpu = HvVmxGetVcpu();
    PVCPU_LOG_STATE logger = &vcpu->log_state;
    UINT32 cur_head = 0;
    UINT32 cur_tail = 0;
    UINT32 usage = 0;
    UINT32 old_head = 0;
    UINT32 index = 0;
    PLOG_ENTRY entry = NULL;
    va_list args = NULL;

    if (vcpu->state == VMX_VCPU_STATE_TERMINATING)
        return;

    if (logger->flushing) {
        InterlockedIncrement(&logger->flush_miss_count);
        return;
    }

    cur_head = logger->head;
    cur_tail = logger->tail;
    usage = cur_head - cur_tail;

    // Check if we should log based on level
    if (!HvLogShouldLog(&g_LogConfig, Level)) {
        return;
    }

    if (usage >= VMX_MAX_LOG_ENTRIES_COUNT) {
        InterlockedIncrement(&logger->discard_count);
        return;
    }

    // Format the log message with metadata based on configuration
    CHAR formatted_message[LOG_DEFAULT_MAX_MESSAGE_LENGTH];
    CHAR timestamp[32];
    CHAR category_str[32];
    
    // Get timestamp if enabled
    if (g_LogConfig.enable_timestamps) {
        LARGE_INTEGER system_time;
        KeQuerySystemTime(&system_time);
        TIME_FIELDS time_fields;
        RtlTimeToTimeFields(&system_time, &time_fields);
        RtlStringCbPrintfA(timestamp, sizeof(timestamp), "%02d:%02d:%02d.%03d",
            time_fields.Hour, time_fields.Minute, time_fields.Second, time_fields.Milliseconds);
    }

    // Get category string if enabled
    if (g_LogConfig.enable_categories) {
        switch (Category) {
            case LOG_CATEGORY_GENERAL: RtlStringCbCopyA(category_str, sizeof(category_str), "GENERAL"); break;
            case LOG_CATEGORY_VMX: RtlStringCbCopyA(category_str, sizeof(category_str), "VMX"); break;
            case LOG_CATEGORY_VMCS: RtlStringCbCopyA(category_str, sizeof(category_str), "VMCS"); break;
            case LOG_CATEGORY_HYPERCALL: RtlStringCbCopyA(category_str, sizeof(category_str), "HYPERCALL"); break;
            case LOG_CATEGORY_PERFORMANCE: RtlStringCbCopyA(category_str, sizeof(category_str), "PERF"); break;
            case LOG_CATEGORY_SECURITY: RtlStringCbCopyA(category_str, sizeof(category_str), "SECURITY"); break;
            default: RtlStringCbCopyA(category_str, sizeof(category_str), "UNKNOWN"); break;
        }
    }

    old_head = InterlockedIncrement(&logger->head) - 1;
    index = old_head % VMX_MAX_LOG_ENTRIES_COUNT;
    entry = &logger->logs[index];
    entry->timestamp = __rdtsc();

    va_start(args, Format);
    status = RtlStringCbVPrintfA(
        entry->message,
        VMX_INIDIVIDUAL_LOG_MAX_SIZE,
        Format,
        args);
    va_end(args);

    if (!NT_SUCCESS(status)) {
        InterlockedIncrement(&logger->discard_count);
        return;
    }

    InterlockedIncrement(&logger->log_count);

    if (HvpLogCheckToFlush(logger))
        HvLogFlush(logger);
}

/**
 * @brief Logs an informational message.
 *
 * This function logs a message with the INFO level, which is typically used
 * for general information about the application's operation.
 *
 * @param Format - The format string for the log message.
 * @param ... - Additional arguments for the format string.
 */
VOID LogInfo(
    _In_ PCSTR Format,
    ...
)
{
    va_list args;
    va_start(args, Format);
    LogMessage(LOG_LEVEL_INFO, Format, args);
    va_end(args);
}

/**
 * @brief Logs an error message.
 *
 * This function logs a message with the ERROR level, which is typically used
 * for reporting errors that require attention.
 *
 * @param Format - The format string for the log message.
 * @param ... - Additional arguments for the format string.
 */
VOID LogError(
    _In_ PCSTR Format,
    ...
)
{
    va_list args;
    va_start(args, Format);
    LogMessage(LOG_LEVEL_ERROR, Format, args);
    va_end(args);
}

#endif
#pragma warning(pop)