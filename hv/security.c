#include "security.h"
#include "log.h"
#include "vmx.h"

// Global security configuration
static SECURITY_CONFIG g_SecurityConfig = {0};
static PSECURITY_VIOLATION_CALLBACK g_ViolationCallback = NULL;
static PVOID g_ViolationContext = NULL;

NTSTATUS
SecurityInitialize(
    PSECURITY_CONFIG Config
)
{
    NTSTATUS status = STATUS_SUCCESS;

    if (!Config) {
        return STATUS_INVALID_PARAMETER;
    }

    // Copy configuration
    RtlCopyMemory(&g_SecurityConfig, Config, sizeof(SECURITY_CONFIG));

    // Initialize TME if enabled
    if (g_SecurityConfig.Features & SECURITY_FEATURE_TME_ENABLED) {
        status = VmxEnableTme(g_SecurityConfig.MemoryEncryptionKey);
        if (!NT_SUCCESS(status)) {
            LogError("Failed to enable TME: 0x%X", status);
            return status;
        }
    }

    // Initialize TDX if enabled
    if (g_SecurityConfig.Features & SECURITY_FEATURE_TDX_ENABLED) {
        status = VmxEnableTdx();
        if (!NT_SUCCESS(status)) {
            LogError("Failed to enable TDX: 0x%X", status);
            return status;
        }
    }

    // Initialize TPM if enabled
    if (g_SecurityConfig.Features & SECURITY_FEATURE_TPM_ENABLED) {
        status = VmxEnableTpm(g_SecurityConfig.TpmVersion);
        if (!NT_SUCCESS(status)) {
            LogError("Failed to enable TPM: 0x%X", status);
            return status;
        }
    }

    LogInfo("Security features initialized successfully");
    return status;
}

VOID
SecurityEnableFeature(
    UINT32 Feature
)
{
    g_SecurityConfig.Features |= Feature;
    LogInfo("Security feature 0x%X enabled", Feature);
}

VOID
SecurityDisableFeature(
    UINT32 Feature
)
{
    g_SecurityConfig.Features &= ~Feature;
    LogInfo("Security feature 0x%X disabled", Feature);
}

BOOLEAN
SecurityIsFeatureEnabled(
    UINT32 Feature
)
{
    return (g_SecurityConfig.Features & Feature) != 0;
}

NTSTATUS
SecurityRegisterViolationCallback(
    PSECURITY_VIOLATION_CALLBACK Callback,
    PVOID Context
)
{
    if (!Callback) {
        return STATUS_INVALID_PARAMETER;
    }

    g_ViolationCallback = Callback;
    g_ViolationContext = Context;

    return STATUS_SUCCESS;
}

VOID
SecurityHandleViolation(
    SECURITY_VIOLATION_TYPE ViolationType,
    PVOID Context
)
{
    // Log the violation
    LogWarning("Security violation detected: %d", ViolationType);

    // Call the registered callback if any
    if (g_ViolationCallback) {
        g_ViolationCallback(ViolationType, g_ViolationContext);
    }

    // Additional handling based on violation type
    switch (ViolationType) {
        case ViolationTypeMemoryAccess:
            // Handle memory access violation
            break;
        case ViolationTypePrivilegeEscalation:
            // Handle privilege escalation attempt
            break;
        case ViolationTypeResourceExhaustion:
            // Handle resource exhaustion
            break;
        case ViolationTypeSideChannel:
            // Handle side channel attack
            break;
        default:
            // Handle unknown violation
            break;
    }
} 