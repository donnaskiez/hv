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

// Dynamic Resource Allocation and QoS Guarantees
typedef struct _RESOURCE_ALLOC_CONFIG {
    UINT32 CpuQuota;
    UINT32 Priority;
    UINT32 MinGuarantee;
    UINT32 MaxLimit;
    UINT64 MemoryQuota;
    UINT64 IoQuota;
    UINT64 NetworkQuota;
} RESOURCE_ALLOC_CONFIG, *PRESOURCE_ALLOC_CONFIG;

// Virtual Device Emulation
typedef struct _VIRTUAL_DEVICE_CONFIG {
    UINT32 DeviceType;
    UINT32 BusType;
    UINT32 VendorId;
    UINT32 DeviceId;
    UINT64 BaseAddress;
    UINT64 Size;
    BOOLEAN EnablePassthrough;
} VIRTUAL_DEVICE_CONFIG, *PVIRTUAL_DEVICE_CONFIG;

// Hardware-Assisted Virtualization Features
typedef struct _HARDWARE_ASSIST_CONFIG {
    BOOLEAN VtdEnabled;
    BOOLEAN SrIovEnabled;
    UINT32 VirtualFunctions;
    BOOLEAN PostedInterrupts;
} HARDWARE_ASSIST_CONFIG, *PHARDWARE_ASSIST_CONFIG;

// Memory Ballooning and Page Sharing
typedef struct _MEMORY_BALLOON_CONFIG {
    UINT64 TargetSize;
    UINT32 BalloonSpeed;
    UINT32 DeflateSpeed;
    BOOLEAN EnableSharing;
    UINT32 SharingThreshold;
} MEMORY_BALLOON_CONFIG, *PMEMORY_BALLOON_CONFIG;

// Virtual TPM Support
typedef struct _VIRTUAL_TPM_CONFIG {
    UINT32 Version;
    UINT32 Family;
    UINT32 Level;
    UINT32 Revision;
    BOOLEAN EnableAttestation;
    UINT32 KeySize;
} VIRTUAL_TPM_CONFIG, *PVIRTUAL_TPM_CONFIG;

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
    PRESOURCE_ALLOC_CONFIG Config
);

NTSTATUS
AdvancedVirtCreateVirtualDevice(
    UINT32 VmId,
    PVIRTUAL_DEVICE_CONFIG Config,
    PUINT32 DeviceId
);

NTSTATUS
AdvancedVirtConfigureHardwareAssist(
    UINT32 VmId,
    PHARDWARE_ASSIST_CONFIG Config
);

NTSTATUS
AdvancedVirtConfigureMemoryBalloon(
    UINT32 VmId,
    PMEMORY_BALLOON_CONFIG Config
);

NTSTATUS
AdvancedVirtConfigureVirtualTpm(
    UINT32 VmId,
    PVIRTUAL_TPM_CONFIG Config
);

NTSTATUS
AdvancedVirtAttestVirtualTpm(
    UINT32 VmId,
    PVOID AttestationData,
    PUINT32 DataSize
); 