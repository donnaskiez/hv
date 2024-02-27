#include "log.h"

#include <ntstrsafe.h>

#include <stdarg.h>

STATIC
VOID
LogFlushLogsDpcRoutine(_In_ PKDPC*    Dpc,
                       _In_opt_ PVOID DeferredContext,
                       _In_opt_ PVOID SystemArgument1,
                       _In_opt_ PVOID SystemArgument2)
{
        PVCPU_LOG_STATE log  = (PVCPU_LOG_STATE)DeferredContext;
        UINT32          core = KeGetCurrentProcessorNumber();
        KIRQL           irql = {0};

        if (!log)
                return;

        HighIrqlLockAcquire(&log->lock);

        for (UINT64 index = 0; index < log->current_log_count; index++) {
                PCSTR string = (UINT64)log->log_buffer + index * VMX_INIDIVIDUAL_LOG_MAX_SIZE;
                DEBUG_LOG("%s", string);
        }

        RtlZeroMemory(log->log_buffer, VMX_LOG_BUFFER_SIZE);
        log->current_log_count = 0;
        HighIrqlLockRelease(&log->lock);
}

NTSTATUS
InitialiseVcpuLogger(_In_ PVIRTUAL_MACHINE_STATE Vcpu)
{
        Vcpu->log_state.current_log_count = 0;

        KeInitializeDpc(&Vcpu->log_state.dpc, LogFlushLogsDpcRoutine, &Vcpu->log_state);
        HighIrqlLockInitialise(&Vcpu->log_state.lock);

        Vcpu->log_state.log_buffer =
            ExAllocatePool2(POOL_FLAG_NON_PAGED, VMX_LOG_BUFFER_SIZE, VMX_LOG_BUFFER_POOL_TAG);

        if (!Vcpu->log_state.log_buffer)
                return STATUS_MEMORY_NOT_ALLOCATED;

        return STATUS_SUCCESS;
}

BOOLEAN
CheckToFlushLogs(_In_ PVIRTUAL_MACHINE_STATE Vcpu)
{
        return Vcpu->log_state.current_log_count == VMX_MAX_LOG_ENTRIES_COUNT ? TRUE : FALSE;
}

/*
 * Since I can't be bothered to write my own "safe" implementation of vsprintf, I am opting to use
 * RtlStringCbVPrintfA. Now RtlStringCbVPrintfA according to the documentation can only be run at
 * IRQL = PASSIVE_LEVEL. However, DbgPrint can be used at IRQL <= DIRQL and I am assuming it uses
 * RtlStringCbVPrintfA to convert the variadic arguments into the final string to be logged.
 * However, this is only true for non wide string arguments. Now I am not sure why this can't be
 * used at HIGH_LEVEL but I am risking it since this is not a production ready project anyway and
 * more for just fun and learning purposes.
 */
VOID
LogToBuffer(PCSTR Format, ...)
{
        PVCPU_LOG_STATE log         = &vmm_state[KeGetCurrentProcessorNumber()].log_state;
        UINT64          destination = 0;
        NTSTATUS        status      = STATUS_UNSUCCESSFUL;
        va_list         args        = {0};

        HighIrqlLockAcquire(&log->lock);

        if (log->current_log_count >= VMX_MAX_LOG_ENTRIES_COUNT)
                goto end;

        destination =
            (UINT64)log->log_buffer + (UINT64)log->current_log_count * VMX_INIDIVIDUAL_LOG_MAX_SIZE;

        va_start(args, Format);
        status = RtlStringCbVPrintfA(destination, VMX_INIDIVIDUAL_LOG_MAX_SIZE, Format, args);
        va_end(args);

        if (!NT_SUCCESS(status))
                goto end;

        log->current_log_count++;

end:
        HighIrqlLockRelease(&log->lock);
}