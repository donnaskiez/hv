#include "vmx_config.h"
#include "log.h"
#include "vmx.h"

// Initialize VMX configuration with default values
NTSTATUS HvVmxConfigInitialize(_Out_ PVMX_FEATURE_CONFIG Config) {
    if (!Config) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Config, sizeof(VMX_FEATURE_CONFIG));
    HvVmxConfigGetDefaults(Config);

    HV_LOG_INFO(LOG_CATEGORY_VMX, "VMX configuration initialized with default values");
    return STATUS_SUCCESS;
}

// Apply configuration to a VCPU
VOID HvVmxConfigApply(_In_ PVCPU Vcpu, _In_ PVMX_FEATURE_CONFIG Config) {
    // CPU Features
    if (Config->cpu_features.enable_preemption_timer) {
        Vcpu->pin_ctls.ActivateVmxPreemptionTimer = TRUE;
        Vcpu->exit_ctls.SaveVmxPreemptionTimerValue = TRUE;
        Vcpu->preemption_time = Config->performance.preemption_timeout;
    }

    // Performance settings
    if (Config->performance.enable_caching) {
        Vcpu->proc_ctls2.EnableRdtscp = TRUE;
        Vcpu->proc_ctls2.EnableInvpcid = TRUE;
    }

    // Debug settings
    if (Config->debug.enable_debug_exceptions) {
        Vcpu->exception_bitmap |= EXCEPTION_DEBUG;
    }
    if (Config->debug.monitor_cr_access) {
        Vcpu->proc_ctls.Cr3LoadExiting = TRUE;
        Vcpu->proc_ctls.Cr3StoreExiting = TRUE;
    }
    if (Config->debug.monitor_dr_access) {
        Vcpu->proc_ctls.MovDrExiting = TRUE;
    }

    // I/O Control settings
    if (Config->io_control.intercept_all_io) {
        Vcpu->proc_ctls.UnconditionalIoExiting = TRUE;
    } else if (Config->io_control.enable_io_bitmaps) {
        Vcpu->proc_ctls.UseIoBitmaps = TRUE;
    }

    if (Config->io_control.enable_msr_bitmaps) {
        Vcpu->proc_ctls.UseMsrBitmaps = TRUE;
    }

    // Update VMCS with new configuration
    HvVmcsSyncConfiguration(Vcpu);

    HV_LOG_INFO(LOG_CATEGORY_VMX, "Applied VMX configuration to VCPU %d", KeGetCurrentProcessorNumber());
}

// Validate configuration settings
BOOLEAN HvVmxConfigValidate(_In_ PVMX_FEATURE_CONFIG Config) {
    if (!Config) {
        return FALSE;
    }

    // Validate memory settings
    if (Config->memory.host_stack_size < PAGE_SIZE || 
        Config->memory.guest_stack_size < PAGE_SIZE) {
        HV_LOG_ERROR(LOG_CATEGORY_VMX, "Invalid stack size configuration");
        return FALSE;
    }

    // Validate performance settings
    if (Config->performance.preemption_timeout == 0) {
        HV_LOG_ERROR(LOG_CATEGORY_VMX, "Invalid preemption timeout value");
        return FALSE;
    }

    // Validate I/O settings
    if (Config->io_control.io_bitmap_size > 0x10000) {
        HV_LOG_ERROR(LOG_CATEGORY_VMX, "Invalid I/O bitmap size");
        return FALSE;
    }

    return TRUE;
}

// Set default configuration values
VOID HvVmxConfigGetDefaults(_Out_ PVMX_FEATURE_CONFIG Config) {
    // CPU Features
    Config->cpu_features.enable_preemption_timer = TRUE;
    Config->cpu_features.enable_unrestricted = TRUE;

    // Memory Management
    Config->memory.host_stack_size = VMX_DEFAULT_HOST_STACK_SIZE;
    Config->memory.guest_stack_size = VMX_DEFAULT_GUEST_STACK_SIZE;
    Config->memory.enable_huge_pages = FALSE;

    // Performance Options
    Config->performance.optimize_tlb_flush = TRUE;
    Config->performance.enable_caching = TRUE;
    Config->performance.preemption_timeout = VMX_DEFAULT_PREEMPTION_TIMEOUT;
    Config->performance.msr_bitmap_optimization = 2;

    // Debug Options
    Config->debug.enable_debug_exceptions = TRUE;
    Config->debug.trap_invalid_msr = TRUE;
    Config->debug.monitor_cr_access = TRUE;

    // Security Options
    Config->security.enforce_nx = TRUE;
    Config->security.enable_smap = TRUE;
    Config->security.enable_smep = TRUE;

    // I/O Control
    Config->io_control.enable_io_bitmaps = TRUE;
    Config->io_control.enable_msr_bitmaps = TRUE;
    Config->io_control.io_bitmap_size = VMX_DEFAULT_IO_BITMAP_SIZE;
}