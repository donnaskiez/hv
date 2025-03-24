#include "log.h"
#include "common.h"

#include <ntstrsafe.h>
#include <stdarg.h>

/* flush them every 1 second (unused in this snippet unless you create a timer)
 */
#define LOGS_FLUSH_TIMER_INVOKE_TIME 1000

#if DEBUG

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

    PVCPU_LOG_STATE p_state = (PVCPU_LOG_STATE)DeferredContext;
    UINT32 local_head = 0;
    UINT32 local_tail = 0;
    UINT32 index = 0;
    PLOG_ENTRY log_entry = NULL;

    DEBUG_LOG("Flushing logs!");

    /* no need to check for valid context, assert used instead */
    local_head = p_state->head;
    local_tail = p_state->tail;

    while (local_tail < local_head) {
        index = local_tail % VMX_MAX_LOG_ENTRIES_COUNT;
        log_entry = &p_state->logs[index];

        /* DPC runs on the same core, hence can defer work here */
        DEBUG_LOG(
            "[CPU: %lu][TSC: %llu] %s",
            KeGetCurrentProcessorNumber(),
            log_entry->timestamp,
            log_entry->message);

        local_tail++;
    }

    p_state->tail = local_tail;
}

VOID
HvLogCleanup(_In_ PVIRTUAL_MACHINE_STATE Vcpu)
{
    UNREFERENCED_PARAMETER(Vcpu);

    KeFlushQueuedDpcs();

    DEBUG_LOG(
        "Vcpu: %lx - log count: %llx",
        KeGetCurrentProcessorNumber(),
        Vcpu->log_state.log_count);

    DEBUG_LOG(
        "Vcpu: %lx - discard count: %llx",
        KeGetCurrentProcessorNumber(),
        Vcpu->log_state.discard_count);
}

NTSTATUS
HvLogInitialise(_In_ PVIRTUAL_MACHINE_STATE Vcpu)
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
    UINT32 usage = Logger->head - Logger->tail;
    UINT32 threshold = (UINT32)((VMX_MAX_LOG_ENTRIES_COUNT * 80) / 100);
    return (usage >= threshold) ? TRUE : FALSE;
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
HvLogWrite(PCSTR Format, ...)
{
    PVIRTUAL_MACHINE_STATE vcpu = &vmm_state[KeGetCurrentProcessorNumber()];
    PVCPU_LOG_STATE logger = &vcpu->log_state;
    UINT32 cur_head = 0;
    UINT32 cur_tail = 0;
    UINT32 usage = 0;
    UINT32 old_head = 0;
    UINT32 index = 0;
    LOG_ENTRY* entry = NULL;
    CHAR user_buffer[512] = {0};
    va_list args;
    NTSTATUS status = 0;
    size_t user_len = 0;

    if (vcpu->state == VMX_VCPU_STATE_TERMINATING)
        return;

    cur_head = logger->head;
    cur_tail = logger->tail;
    usage = cur_head - cur_tail;

    if (usage >= VMX_MAX_LOG_ENTRIES_COUNT) {
        InterlockedIncrement((volatile LONG*)&logger->discard_count);
        return;
    }

    old_head = InterlockedIncrement((volatile LONG*)&logger->head) - 1;
    index = old_head % VMX_MAX_LOG_ENTRIES_COUNT;
    entry = &logger->logs[index];
    entry->timestamp = __rdtsc();

    va_start(args, Format);
    status =
        RtlStringCbVPrintfA(user_buffer, sizeof(user_buffer), Format, args);
    va_end(args);

    if (!NT_SUCCESS(status)) {
        InterlockedIncrement((volatile LONG*)&logger->discard_count);
        return;
    }

    user_len = strnlen_s(user_buffer, sizeof(user_buffer));
    if (user_len >= sizeof(entry->message)) {
        RtlCopyMemory(entry->message, user_buffer, sizeof(entry->message) - 1);
        entry->message[sizeof(entry->message) - 1] = '\0';
    }
    else {
        RtlCopyMemory(entry->message, user_buffer, user_len + 1);
    }

    InterlockedIncrement((volatile LONG*)&logger->log_count);

    if (HvpLogCheckToFlush(logger)) {
        KeInsertQueueDpc(&logger->dpc, NULL, NULL);
    }
}

#endif
