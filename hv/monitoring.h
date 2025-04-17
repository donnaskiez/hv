#pragma once

#include "common.h"

// Performance counter types
typedef enum _PERF_COUNTER_TYPE {
    PerfCounterCpu,
    PerfCounterMemory,
    PerfCounterDisk,
    PerfCounterNetwork,
    PerfCounterVmExit,
    PerfCounterCustom
} PERF_COUNTER_TYPE;

// Performance counter structure
typedef struct _PERF_COUNTER {
    PERF_COUNTER_TYPE Type;
    UINT64 Value;
    UINT64 Timestamp;
    CHAR Name[64];
} PERF_COUNTER, *PPERF_COUNTER;

// Dashboard configuration
typedef struct _DASHBOARD_CONFIG {
    UINT32 UpdateInterval;
    UINT32 MaxHistorySize;
    BOOLEAN EnableAlerts;
    BOOLEAN EnableTrending;
} DASHBOARD_CONFIG, *PDASHBOARD_CONFIG;

// Alert configuration
typedef struct _ALERT_CONFIG {
    UINT32 Threshold;
    UINT32 Duration;
    CHAR Message[256];
} ALERT_CONFIG, *PALERT_CONFIG;

// Function declarations
NTSTATUS
MonitoringInitialize(
    PDASHBOARD_CONFIG Config
);

NTSTATUS
MonitoringRegisterCounter(
    PPERF_COUNTER Counter
);

NTSTATUS
MonitoringUnregisterCounter(
    PPERF_COUNTER Counter
);

NTSTATUS
MonitoringUpdateCounter(
    PPERF_COUNTER Counter,
    UINT64 Value
);

NTSTATUS
MonitoringConfigureAlert(
    PERF_COUNTER_TYPE Type,
    PALERT_CONFIG Config
);

NTSTATUS
MonitoringStartTrending(
    PERF_COUNTER_TYPE Type,
    UINT32 Interval
);

NTSTATUS
MonitoringStopTrending(
    PERF_COUNTER_TYPE Type
);

NTSTATUS
MonitoringGetHistory(
    PERF_COUNTER_TYPE Type,
    PPERF_COUNTER* History,
    PUINT32 Count
);

NTSTATUS
MonitoringExportData(
    PERF_COUNTER_TYPE Type,
    PCHAR FilePath
); 