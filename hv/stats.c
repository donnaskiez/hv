#include "stats.h"
#include "log.h"
#include <intrin.h>

// Initialize statistics tracking for a VCPU
VOID HvStatsInitialize(_In_ PVCPU Vcpu) {
    PVMX_PERF_COUNTERS stats = &Vcpu->perf_counters;
    RtlZeroMemory(stats, sizeof(VMX_PERF_COUNTERS));
    
    stats->start_timestamp = __rdtsc();
    stats->last_update = stats->start_timestamp;
    stats->min_exit_latency = MAXUINT64;
    
    HV_LOG_INFO(LOG_CATEGORY_PERFORMANCE, "Statistics tracking initialized for VCPU %d", KeGetCurrentProcessorNumber());
}

// Reset all statistics counters
VOID HvStatsReset(_In_ PVCPU Vcpu) {
    PVMX_PERF_COUNTERS stats = &Vcpu->perf_counters;
    RtlZeroMemory(stats, sizeof(VMX_PERF_COUNTERS));
    
    stats->start_timestamp = __rdtsc();
    stats->last_update = stats->start_timestamp;
    stats->min_exit_latency = MAXUINT64;
    
    HV_LOG_INFO(LOG_CATEGORY_PERFORMANCE, "Statistics reset for VCPU %d", KeGetCurrentProcessorNumber());
}

// Update exit handling latency statistics
VOID HvStatsUpdateExitLatency(_In_ PVCPU Vcpu, _In_ UINT64 ExitLatency) {
    PVMX_PERF_COUNTERS stats = &Vcpu->perf_counters;
    
    // Update min/max latencies
    if (ExitLatency < stats->min_exit_latency) {
        stats->min_exit_latency = ExitLatency;
    }
    if (ExitLatency > stats->max_exit_latency) {
        stats->max_exit_latency = ExitLatency;
    }
    
    // Update average latency
    stats->avg_exit_latency = (stats->avg_exit_latency * stats->total_exits + ExitLatency) / (stats->total_exits + 1);
}

// Record VM exit event
VOID HvStatsRecordExit(_In_ PVCPU Vcpu, _In_ UINT64 ExitReason) {
    PVMX_PERF_COUNTERS stats = &Vcpu->perf_counters;
    
    InterlockedIncrement64(&stats->total_exits);
    if (ExitReason < 64) {
        InterlockedIncrement64(&stats->exit_reason_counts[ExitReason]);
    }
    
    // Update root mode timing
    UINT64 current_tsc = __rdtsc();
    stats->total_cycles_in_root += current_tsc - stats->last_update;
    stats->last_update = current_tsc;
}

// Record VM entry event
VOID HvStatsRecordEntry(_In_ PVCPU Vcpu) {
    PVMX_PERF_COUNTERS stats = &Vcpu->perf_counters;
    
    InterlockedIncrement64(&stats->total_entries);
    
    // Update VMX mode timing
    UINT64 current_tsc = __rdtsc();
    stats->total_cycles_in_vmx += current_tsc - stats->last_update;
    stats->last_update = current_tsc;
}

// Update memory-related statistics
VOID HvStatsUpdateMemoryStats(_In_ PVCPU Vcpu, _In_ UINT64 EventType) {
    PVMX_PERF_COUNTERS stats = &Vcpu->perf_counters;
    
    switch (EventType) {
        case 0: // EPT violation
            InterlockedIncrement64(&stats->ept_violations);
            break;
        case 1: // Page fault
            InterlockedIncrement64(&stats->page_faults);
            break;
        case 2: // TLB flush
            InterlockedIncrement64(&stats->tlb_flushes);
            break;
    }
}

// Update MSR access statistics
VOID HvStatsUpdateMsrStats(_In_ PVCPU Vcpu, _In_ BOOLEAN IsWrite) {
    PVMX_PERF_COUNTERS stats = &Vcpu->perf_counters;
    
    if (IsWrite) {
        InterlockedIncrement64(&stats->msr_writes);
    } else {
        InterlockedIncrement64(&stats->msr_reads);
    }
}

// Update I/O operation statistics
VOID HvStatsUpdateIoStats(_In_ PVCPU Vcpu, _In_ BOOLEAN IsMmio) {
    PVMX_PERF_COUNTERS stats = &Vcpu->perf_counters;
    
    if (IsMmio) {
        InterlockedIncrement64(&stats->mmio_accesses);
    } else {
        InterlockedIncrement64(&stats->io_instructions);
    }
}

// Update CR access statistics
VOID HvStatsUpdateCrStats(_In_ PVCPU Vcpu, _In_ UINT64 CrNumber) {
    PVMX_PERF_COUNTERS stats = &Vcpu->perf_counters;
    
    switch (CrNumber) {
        case 0:
            InterlockedIncrement64(&stats->cr0_accesses);
            break;
        case 3:
            InterlockedIncrement64(&stats->cr3_accesses);
            break;
        case 4:
            InterlockedIncrement64(&stats->cr4_accesses);
            break;
    }
}