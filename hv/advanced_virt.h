#pragma once

#include "common.h"

// APIC virtualization modes
typedef enum _APIC_VIRT_MODE {
    ApicVirtDisabled,
    ApicVirtBasic,
    ApicVirtAdvanced,
    ApicVirtX2Apic
} APIC_VIRT_MODE;

// EPT configuration
typedef struct _EPT_CONFIG {
    UINT32 PageWalkLevels;
    BOOLEAN EnableLargePages;
    BOOLEAN EnableAccessDirty;
    UINT32 CacheType;
} EPT_CONFIG, *PEPT_CONFIG;

// VMCS shadow configuration
typedef struct _VMCS_SHADOW_CONFIG {
    BOOLEAN EnableShadowing;
    UINT32 ShadowCount;
    UINT64 ShadowAddress;
} VMCS_SHADOW_CONFIG, *PVMCS_SHADOW_CONFIG;

// Multi-VM configuration
typedef struct _MULTI_VM_CONFIG {
    UINT32 MaxVMs;
    UINT32 CpuQuota;
    UINT64 MemoryQuota;
    BOOLEAN EnableIsolation;
} MULTI_VM_CONFIG, *PMULTI_VM_CONFIG;

// Snapshot configuration
typedef struct _SNAPSHOT_CONFIG {
    BOOLEAN EnableLiveMigration;
    UINT32 CheckpointInterval;
    UINT64 MaxDowntime;
} SNAPSHOT_CONFIG, *PSNAPSHOT_CONFIG;

// Function declarations
NTSTATUS
AdvancedVirtInitialize(
    VOID
);

NTSTATUS
AdvancedVirtConfigureApic(
    APIC_VIRT_MODE Mode
);

NTSTATUS
AdvancedVirtConfigureEpt(
    PEPT_CONFIG Config
);

NTSTATUS
AdvancedVirtConfigureVmcsShadow(
    PVMCS_SHADOW_CONFIG Config
);

NTSTATUS
AdvancedVirtConfigureMultiVm(
    PMULTI_VM_CONFIG Config
);

NTSTATUS
AdvancedVirtCreateSnapshot(
    UINT32 VmId,
    PSNAPSHOT_CONFIG Config
);

NTSTATUS
AdvancedVirtRestoreSnapshot(
    UINT32 VmId,
    UINT64 SnapshotId
);

NTSTATUS
AdvancedVirtLiveMigrate(
    UINT32 SourceVmId,
    UINT32 TargetVmId,
    UINT64 MaxDowntime
);

NTSTATUS
AdvancedVirtConfigureDynamicResources(
    UINT32 VmId,
    UINT32 CpuQuota,
    UINT64 MemoryQuota
);

NTSTATUS
AdvancedVirtEnableDeviceEmulation(
    UINT32 VmId,
    UINT32 DeviceType
);

NTSTATUS
AdvancedVirtConfigureHardwareAssist(
    UINT32 VmId,
    UINT32 Features
); 