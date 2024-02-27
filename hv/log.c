#include "log.h"

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

        DEBUG_LOG("Entries: %lx", log->current_log_count);

        for (UINT32 index = 0; index < log->current_log_count; index++) {
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
        if (Vcpu->log_state.current_log_count == VMX_MAX_LOG_ENTRIES_COUNT)
                return TRUE;
        return FALSE;
}

VOID
LogToBuffer(PCSTR Format, ...)
{
        PVCPU_LOG_STATE log         = &vmm_state[KeGetCurrentProcessorNumber()].log_state;
        UINT64          destination = 0;

        if (strlen(Format) > VMX_INIDIVIDUAL_LOG_MAX_SIZE)
                return;

        HighIrqlLockAcquire(&log->lock);

        if (log->current_log_count >= VMX_MAX_LOG_ENTRIES_COUNT)
                return;

        destination =
            (UINT64)log->log_buffer + (UINT64)log->current_log_count * VMX_INIDIVIDUAL_LOG_MAX_SIZE;

        RtlCopyMemory((PVOID)destination, Format, strlen(Format));
        log->current_log_count++;
        HighIrqlLockRelease(&log->lock);
}