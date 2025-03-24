#include "log.h"

#include "common.h"

#include <ntstrsafe.h>
#include <stdarg.h>

/* flush them every 1 second */
#define LOGS_FLUSH_TIMER_INVOKE_TIME 1000

#if DEBUG

STATIC
VOID
HvpLogDpcFlushRoutine(_In_ PKDPC*    Dpc,
                      _In_opt_ PVOID DeferredContext,
                      _In_opt_ PVOID SystemArgument1,
                      _In_opt_ PVOID SystemArgument2)
{
        UNREFERENCED_PARAMETER(Dpc);
        UNREFERENCED_PARAMETER(SystemArgument1);
        UNREFERENCED_PARAMETER(SystemArgument2);

        PVCPU_LOG_STATE pState = (PVCPU_LOG_STATE)DeferredContext;
        if (!pState) {
                return;
        }

        // Snapshot of head
        UINT32 localHead = pState->head;
        UINT32 localTail = pState->tail;

        // Enumerate everything from tail to head-1
        while (localTail < localHead) {
                UINT32     index  = localTail % VMX_MAX_LOG_ENTRIES_COUNT;
                LOG_ENTRY* pEntry = &pState->logs[index];

                // For debugging, just print the message
                // (We can also use pEntry->timestamp if we want)
                DEBUG_LOG("%s", pEntry->message);

                localTail++;
        }

        // Update tail to show we've consumed these entries
        pState->tail = localTail;
}

VOID
HvLogCleanup(_In_ PVIRTUAL_MACHINE_STATE Vcpu)
{
        UNREFERENCED_PARAMETER(Vcpu);
        KeFlushQueuedDpcs();
}

NTSTATUS
HvLogInitialise(_In_ PVIRTUAL_MACHINE_STATE Vcpu)
{
        PVCPU_LOG_STATE state = &Vcpu->log_state;

        // Zero out the ring buffer fields
        state->head          = 0;
        state->tail          = 0;
        state->log_count     = 0;
        state->discard_count = 0;
        RtlZeroMemory(state->logs, sizeof(state->logs));

        // Initialize the DPC object
        KeInitializeDpc(&state->dpc, HvpLogDpcFlushRoutine, state);

        // Optionally set up a timer so we flush automatically every second
        // or you can call KeInsertQueueDpc(...) from somewhere else on-demand

        return STATUS_SUCCESS;
}

BOOLEAN
HvpLogCheckToFlush(_In_ PVCPU_LOG_STATE Logger)
{
        // 'usage' is how many entries are currently in the buffer
        UINT32 usage = Logger->head - Logger->tail;

        // 70% of the total capacity
        UINT32 threshold = (UINT32)((VMX_MAX_LOG_ENTRIES_COUNT * 70) / 100);

        // If usage >= threshold, return TRUE to indicate we should flush
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
        PVCPU_LOG_STATE pLogState =
            &vmm_state[KeGetCurrentProcessorNumber()].log_state;

        UINT32 currentHead = pLogState->head;
        UINT32 currentTail = pLogState->tail;
        UINT32 usage       = currentHead - currentTail;

        if (usage >= VMX_MAX_LOG_ENTRIES_COUNT) {
                InterlockedIncrement((volatile LONG*)&pLogState->discard_count);
                return;
        }

        UINT32 oldHead =
            InterlockedIncrement((volatile LONG*)&pLogState->head) - 1;

        UINT32     index = oldHead % VMX_MAX_LOG_ENTRIES_COUNT;
        LOG_ENTRY* entry = &pLogState->logs[index];

        entry->timestamp = __rdtsc();

        va_list args;
        va_start(args, Format);
        RtlStringCbVPrintfA(
            entry->message, sizeof(entry->message), Format, args);
        va_end(args);

        InterlockedIncrement((volatile LONG*)&pLogState->log_count);

        if (HvpLogCheckToFlush(pLogState))
                KeInsertQueueDpc(&pLogState->dpc, NULL, NULL);
}

#endif