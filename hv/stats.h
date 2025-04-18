#ifndef STATS_H
#define STATS_H

#include "common.h"
#include "vmx.h"

// Performance counters for various VMX operations
typedef struct _VMX_PERF_COUNTERS {
    // VM Entry/Exit statistics
    UINT64 total_entries;           // Total number of VM entries
    UINT64 total_exits;            // Total number of VM exits
    UINT64 total_cycles_in_vmx;    // Total CPU cycles spent in VMX operation
    UINT64 total_cycles_in_root;   // Total CPU cycles spent in root mode
    
    // Exit reason statistics
    UINT64 exit_reason_counts[64];  // Count for each exit reason
    UINT64 max_exit_latency;       // Maximum observed exit handling latency
    UINT64 min_exit_latency;       // Minimum observed exit handling latency
    UINT64 avg_exit_latency;       // Average exit handling latency
    
    // Memory management statistics
    UINT64 ept_violations;         // Number of EPT violations
    UINT64 page_faults;            // Number of page faults handled
    UINT64 tlb_flushes;           // Number of TLB flushes performed
    
    // Interrupt handling statistics
    UINT64 external_interrupts;    // Number of external interrupts
    UINT64 nmi_exits;             // Number of NMI exits
    UINT64 exception_exits;        // Number of exception exits
    
    // MSR access statistics
    UINT64 msr_reads;             // Number of MSR read operations
    UINT64 msr_writes;            // Number of MSR write operations
    
    // I/O operation statistics
    UINT64 io_instructions;       // Number of I/O instructions
    UINT64 mmio_accesses;         // Number of MMIO accesses
    
    // CR access statistics
    UINT64 cr0_accesses;          // Number of CR0 accesses
    UINT64 cr3_accesses;          // Number of CR3 accesses
    UINT64 cr4_accesses;          // Number of CR4 accesses
    
    // Timestamp information
    UINT64 start_timestamp;       // Timestamp when monitoring started
    UINT64 last_update;           // Timestamp of last update
} VMX_PERF_COUNTERS, *PVMX_PERF_COUNTERS;

// Function declarations
VOID HvStatsInitialize(_In_ PVCPU Vcpu);
VOID HvStatsReset(_In_ PVCPU Vcpu);
VOID HvStatsUpdateExitLatency(_In_ PVCPU Vcpu, _In_ UINT64 ExitLatency);
VOID HvStatsRecordExit(_In_ PVCPU Vcpu, _In_ UINT64 ExitReason);
VOID HvStatsRecordEntry(_In_ PVCPU Vcpu);
VOID HvStatsUpdateMemoryStats(_In_ PVCPU Vcpu, _In_ UINT64 EventType);
VOID HvStatsUpdateMsrStats(_In_ PVCPU Vcpu, _In_ BOOLEAN IsWrite);
VOID HvStatsUpdateIoStats(_In_ PVCPU Vcpu, _In_ BOOLEAN IsMmio);
VOID HvStatsUpdateCrStats(_In_ PVCPU Vcpu, _In_ UINT64 CrNumber);

// Helper macros for statistics tracking
#define HV_STATS_RECORD_EXIT(vcpu, reason) HvStatsRecordExit(vcpu, reason)
#define HV_STATS_RECORD_ENTRY(vcpu) HvStatsRecordEntry(vcpu)
#define HV_STATS_UPDATE_LATENCY(vcpu, latency) HvStatsUpdateExitLatency(vcpu, latency)

#endif // STATS_H