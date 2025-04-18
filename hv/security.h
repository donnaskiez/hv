#pragma once

#include "common.h"

// Security feature flags
#define SECURITY_FEATURE_TME_ENABLED     (1 << 0)
#define SECURITY_FEATURE_TDX_ENABLED     (1 << 1)
#define SECURITY_FEATURE_ML_DETECTION    (1 << 2)
#define SECURITY_FEATURE_ZERO_TRUST      (1 << 3)
#define SECURITY_FEATURE_TPM_ENABLED     (1 << 4)

// Security configuration structure
typedef struct _SECURITY_CONFIG {
    UINT32 Features;
    UINT32 MemoryEncryptionKey;
    UINT32 TpmVersion;
    BOOLEAN EnableZeroTrust;
    BOOLEAN EnableMlDetection;
} SECURITY_CONFIG, *PSECURITY_CONFIG;

// Security violation types
typedef enum _SECURITY_VIOLATION_TYPE {
    ViolationTypeMemoryAccess,
    ViolationTypePrivilegeEscalation,
    ViolationTypeResourceExhaustion,
    ViolationTypeSideChannel,
    ViolationTypeUnknown
} SECURITY_VIOLATION_TYPE;

// Security violation callback
typedef VOID (*PSECURITY_VIOLATION_CALLBACK)(
    SECURITY_VIOLATION_TYPE ViolationType,
    PVOID Context
);

// Function declarations
NTSTATUS
SecurityInitialize(
    PSECURITY_CONFIG Config
);

VOID
SecurityEnableFeature(
    UINT32 Feature
);

VOID
SecurityDisableFeature(
    UINT32 Feature
);

BOOLEAN
SecurityIsFeatureEnabled(
    UINT32 Feature
);

NTSTATUS
SecurityRegisterViolationCallback(
    PSECURITY_VIOLATION_CALLBACK Callback,
    PVOID Context
);

VOID
SecurityHandleViolation(
    SECURITY_VIOLATION_TYPE ViolationType,
    PVOID Context
); 