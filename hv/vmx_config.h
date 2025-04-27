#ifndef VMX_CONFIG_H
#define VMX_CONFIG_H

#include "common.h"

// VMX Feature Configuration
typedef struct _VMX_FEATURE_CONFIG {
    // CPU Feature Control
    struct {
        BOOLEAN enable_ept;              // Enable Extended Page Tables
        BOOLEAN enable_vpid;             // Enable VPID
        BOOLEAN enable_unrestricted;     // Enable Unrestricted Guest
        BOOLEAN enable_preemption_timer; // Enable VMX Preemption Timer
        BOOLEAN enable_posted_interrupts;// Enable Posted Interrupts
        BOOLEAN enable_vmfunc;          // Enable VM Functions
        BOOLEAN enable_vmcs_shadowing;  // Enable VMCS Shadowing
        BOOLEAN enable_tsc_scaling;     // Enable TSC Scaling
    } cpu_features;

    // Memory Management
    struct {
        UINT32 host_stack_size;         // Size of host stack in bytes
        UINT32 guest_stack_size;        // Size of guest stack in bytes
        BOOLEAN enable_huge_pages;       // Enable 2MB pages for EPT
        BOOLEAN enable_dirty_logging;    // Enable dirty page logging
    } memory;

    // Performance Options
    struct {
        BOOLEAN optimize_tlb_flush;     // Optimize TLB flush operations
        BOOLEAN enable_caching;         // Enable caching optimizations
        UINT32 preemption_timeout;      // Preemption timer timeout value
        UINT32 msr_bitmap_optimization; // MSR bitmap optimization level (0-3)
    } performance;

    // Debug Options
    struct {
        BOOLEAN enable_debug_exceptions; // Enable debug exceptions
        BOOLEAN trap_invalid_msr;       // Trap invalid MSR access
        BOOLEAN monitor_cr_access;      // Monitor CR register access
        BOOLEAN monitor_dr_access;      // Monitor debug register access
    } debug;

    // Security Options
    struct {
        BOOLEAN enforce_nx;            // Enforce NX bit
        BOOLEAN enable_smap;           // Enable SMAP in guest
        BOOLEAN enable_smep;           // Enable SMEP in guest
        BOOLEAN isolate_address_space; // Isolate guest address spaces
    } security;

    // I/O Control
    struct {
        BOOLEAN intercept_all_io;      // Intercept all I/O operations
        BOOLEAN enable_io_bitmaps;     // Enable I/O bitmaps
        BOOLEAN enable_msr_bitmaps;    // Enable MSR bitmaps
        UINT32 io_bitmap_size;         // Size of I/O bitmap
    } io_control;

} VMX_FEATURE_CONFIG, *PVMX_FEATURE_CONFIG;

/**
 * @brief Structure for VMX configuration.
 *
 * This structure holds the configuration parameters for Virtual Machine Extensions (VMX),
 * including preemption timer, unrestricted mode, and debug options.
 */
typedef struct _VMX_CONFIG {
    BOOLEAN EnablePreemptionTimer; /**< Enable or disable the preemption timer. */
    BOOLEAN EnableUnrestrictedMode; /**< Enable or disable unrestricted mode. */
    BOOLEAN EnableDebugOptions; /**< Enable or disable debug options. */
} VMX_CONFIG, *PVMX_CONFIG;

// Default configuration values
#define VMX_DEFAULT_HOST_STACK_SIZE    0x8000
#define VMX_DEFAULT_GUEST_STACK_SIZE   0x8000
#define VMX_DEFAULT_PREEMPTION_TIMEOUT 5000
#define VMX_DEFAULT_IO_BITMAP_SIZE     0x2000

// Function declarations
NTSTATUS HvVmxConfigInitialize(_Out_ PVMX_FEATURE_CONFIG Config);
VOID HvVmxConfigApply(_In_ PVCPU Vcpu, _In_ PVMX_FEATURE_CONFIG Config);
BOOLEAN HvVmxConfigValidate(_In_ PVMX_FEATURE_CONFIG Config);
VOID HvVmxConfigGetDefaults(_Out_ PVMX_FEATURE_CONFIG Config);

/**
 * @brief Configures VMX settings.
 *
 * This function applies the given VMX configuration to the hypervisor.
 *
 * @param Config - Pointer to the VMX configuration structure.
 *
 * @return NTSTATUS - STATUS_SUCCESS on success, or an error code on failure.
 */
NTSTATUS VmxConfigureSettings(PVMX_CONFIG Config);

#endif // VMX_CONFIG_H