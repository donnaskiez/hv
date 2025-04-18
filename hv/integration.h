#pragma once

#include "common.h"

// Live patching configuration
typedef struct _LIVE_PATCH_CONFIG {
    BOOLEAN EnableLivePatching;
    UINT32 PatchTimeout;
    UINT32 MaxPatchSize;
    BOOLEAN EnableRollback;
} LIVE_PATCH_CONFIG, *PLIVE_PATCH_CONFIG;

// Hot-plug device configuration
typedef struct _HOT_PLUG_CONFIG {
    UINT32 DeviceType;
    UINT32 BusType;
    UINT32 SlotNumber;
    BOOLEAN EnableHotRemove;
} HOT_PLUG_CONFIG, *PHOT_PLUG_CONFIG;

// Cross-platform configuration
typedef struct _CROSS_PLATFORM_CONFIG {
    BOOLEAN EnableWindows;
    BOOLEAN EnableLinux;
    UINT32 PlatformFeatures;
} CROSS_PLATFORM_CONFIG, *PCROSS_PLATFORM_CONFIG;

// Container configuration
typedef struct _CONTAINER_CONFIG {
    BOOLEAN EnableOciSupport;
    UINT32 ContainerLimit;
    UINT64 MemoryLimit;
    UINT32 CpuLimit;
} CONTAINER_CONFIG, *PCONTAINER_CONFIG;

// Storage integration configuration
typedef struct _STORAGE_CONFIG {
    UINT32 BackendType;
    UINT64 MaxSize;
    BOOLEAN EnableEncryption;
    UINT32 PerformanceTier;
} STORAGE_CONFIG, *PSTORAGE_CONFIG;

// Network integration configuration
typedef struct _NETWORK_CONFIG {
    UINT32 SdnControllerType;
    UINT32 VlanId;
    BOOLEAN EnableQos;
    UINT32 BandwidthLimit;
} NETWORK_CONFIG, *PNETWORK_CONFIG;

// Function declarations
NTSTATUS
IntegrationInitialize(
    VOID
);

NTSTATUS
IntegrationConfigureLivePatch(
    PLIVE_PATCH_CONFIG Config
);

NTSTATUS
IntegrationConfigureHotPlug(
    PHOT_PLUG_CONFIG Config
);

NTSTATUS
IntegrationConfigureCrossPlatform(
    PCROSS_PLATFORM_CONFIG Config
);

NTSTATUS
IntegrationConfigureContainer(
    PCONTAINER_CONFIG Config
);

NTSTATUS
IntegrationConfigureStorage(
    PSTORAGE_CONFIG Config
);

NTSTATUS
IntegrationConfigureNetwork(
    PNETWORK_CONFIG Config
);

NTSTATUS
IntegrationApplyLivePatch(
    PVOID PatchData,
    UINT32 PatchSize
);

NTSTATUS
IntegrationHotPlugDevice(
    UINT32 VmId,
    PHOT_PLUG_CONFIG Config
);

NTSTATUS
IntegrationHotRemoveDevice(
    UINT32 VmId,
    UINT32 DeviceId
);

NTSTATUS
IntegrationCreateContainer(
    PCONTAINER_CONFIG Config,
    PUINT32 ContainerId
);

NTSTATUS
IntegrationDestroyContainer(
    UINT32 ContainerId
);

NTSTATUS
IntegrationAttachStorage(
    UINT32 VmId,
    PSTORAGE_CONFIG Config
);

NTSTATUS
IntegrationAttachNetwork(
    UINT32 VmId,
    PNETWORK_CONFIG Config
); 