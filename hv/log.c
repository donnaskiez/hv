#include "log.h"
#include "common.h"

#include <ntstrsafe.h>
#include <stdarg.h>

#pragma warning(push)
#pragma warning(disable : 28182)

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
    NTSTATUS status = STATUS_SUCCESS;
    PVCPU vcpu = &vmm_state[KeGetCurrentProcessorNumber()];
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

    if (usage >= VMX_MAX_LOG_ENTRIES_COUNT) {
        InterlockedIncrement(&logger->discard_count);
        return;
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
        KeInsertQueueDpc(&logger->dpc, NULL, NULL);
}

#endif
#pragma warning(pop)