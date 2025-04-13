#ifndef LIB_H
#define LIB_H

#include "../ia32.h"

#include <windows.h>

#define STATIC static

typedef struct _VCPU_STATS {
    UINT64 exit_count;

    struct {
        UINT64 cpuid;
        UINT64 invd;
        UINT64 vmcall;
        UINT64 mov_cr;
        UINT64 wbinvd;
        UINT64 tpr_threshold;
        UINT64 exception_or_nmi;
        UINT64 trap_flags;
        UINT64 wrmsr;
        UINT64 rdmsr;
        UINT64 mov_dr;
        UINT64 virtualised_eoi;
        UINT64 preemption_timer;
    } reasons;

    struct {
        UINT64 ping;
        UINT64 query_stats;
        UINT64 terminate;

        UINT64 write_proc_ctls;
        UINT64 write_proc_ctls2;
        UINT64 write_pin_ctls;
        UINT64 write_exit_ctls;
        UINT64 write_entry_ctls;
        UINT64 write_exception_bitmap;
        UINT64 write_msr_bitmap;

        UINT64 read_proc_ctls;
        UINT64 read_proc_ctls2;
        UINT64 read_pin_ctls;
        UINT64 read_exit_ctls;
        UINT64 read_entry_ctls;
        UINT64 read_exception_bitmap;
        UINT64 read_msr_bitmap;
    } hypercall;

} VCPU_STATS, *PVCPU_STATS;

#define HVSTATUS_SUCCESS            0
#define HVSTATUS_FAILURE            1
#define HVSTATUS_NOT_HANDLED        2
#define HVSTATUS_INVALID_PARAMETER  3
#define HVSTATUS_INVALID_GUEST_CPL  4
#define HVSTATUS_BUFFER_TOO_SMALL   5
#define HVSTATUS_DEVICE_OPEN_FAIL   6
#define HVSTATUS_INVALID_PING_VALUE 7

typedef ULONG HVSTATUS;

/*
 * VMX Hypercall (and IOCTL Function) IDs
 */
#define VMX_HYPERCALL_FUNCTION_TERMINATE   0x800
#define VMX_HYPERCALL_FUNCTION_PING        0x801
#define VMX_HYPERCALL_FUNCTION_QUERY_STATS 0x802

#define VMX_HYPERCALL_FUNCTION_WRITE_PROC_CTLS        0x803
#define VMX_HYPERCALL_FUNCTION_WRITE_PROC_CTLS2       0x804
#define VMX_HYPERCALL_FUNCTION_WRITE_PIN_CTLS         0x805
#define VMX_HYPERCALL_FUNCTION_WRITE_EXIT_CTLS        0x806
#define VMX_HYPERCALL_FUNCTION_WRITE_ENTRY_CTLS       0x807
#define VMX_HYPERCALL_FUNCTION_WRITE_EXCEPTION_BITMAP 0x808
#define VMX_HYPERCALL_FUNCTION_WRITE_MSR_BITMAP       0x809

#define VMX_HYPERCALL_FUNCTION_READ_PROC_CTLS        0x810
#define VMX_HYPERCALL_FUNCTION_READ_PROC_CTLS2       0x811
#define VMX_HYPERCALL_FUNCTION_READ_PIN_CTLS         0x812
#define VMX_HYPERCALL_FUNCTION_READ_EXIT_CTLS        0x813
#define VMX_HYPERCALL_FUNCTION_READ_ENTRY_CTLS       0x814
#define VMX_HYPERCALL_FUNCTION_READ_EXCEPTION_BITMAP 0x815
#define VMX_HYPERCALL_FUNCTION_READ_MSR_BITMAP       0x816

typedef struct _HYPERCALL_HEADER {
    UINT32 bytes_written; /* bytes written to output buffer */
    UINT32 bytes_read;    /* bytes read from input buffer */
} HYPERCALL_HEADER, *PHYPERCALL_HEADER;

/*
 * IOCTL: IOCTL_HYPERCALL_TERMINATE_VMX
 * Summary: Requests the VMX hypervisor to terminate.
 */
#define IOCTL_HYPERCALL_TERMINATE_VMX     \
    CTL_CODE(                             \
        FILE_DEVICE_UNKNOWN,              \
        VMX_HYPERCALL_FUNCTION_TERMINATE, \
        METHOD_BUFFERED,                  \
        FILE_ANY_ACCESS)

/*
 * IOCTL: IOCTL_HYPERCALL_PING
 * Summary: Sends a "ping" request to the hypervisor.
 */
#define IOCTL_HYPERCALL_PING         \
    CTL_CODE(                        \
        FILE_DEVICE_UNKNOWN,         \
        VMX_HYPERCALL_FUNCTION_PING, \
        METHOD_BUFFERED,             \
        FILE_ANY_ACCESS)

#define HV_VMX_PING_VALUE 999

typedef struct _HYPERCALL_PING {
    HYPERCALL_HEADER header;
    UINT32 value;
} HYPERCALL_PING, *PHYPERCALL_PING;

/*
 * IOCTL: IOCTL_HYPERCALL_QUERY_STATS
 * Summary: Requests current VMX execution statistics.
 */
#define IOCTL_HYPERCALL_QUERY_STATS         \
    CTL_CODE(                               \
        FILE_DEVICE_UNKNOWN,                \
        VMX_HYPERCALL_FUNCTION_QUERY_STATS, \
        METHOD_BUFFERED,                    \
        FILE_ANY_ACCESS)

typedef struct _HYPERCALL_QUERY_STATS {
    HYPERCALL_HEADER header;
    VCPU_STATS stats;
} HYPERCALL_QUERY_STATS, *PHYPERCALL_QUERY_STATS;

/*
 * IOCTL: IOCTL_HYPERCALL_WRITE_PROC_CTLS
 * IOCTL: IOCTL_HYPERCALL_READ_PROC_CTLS
 * Summary: Reads or updates the primary processor-based VMCS controls.
 */
#define IOCTL_HYPERCALL_WRITE_PROC_CTLS         \
    CTL_CODE(                                   \
        FILE_DEVICE_UNKNOWN,                    \
        VMX_HYPERCALL_FUNCTION_WRITE_PROC_CTLS, \
        METHOD_BUFFERED,                        \
        FILE_ANY_ACCESS)

#define IOCTL_HYPERCALL_READ_PROC_CTLS         \
    CTL_CODE(                                  \
        FILE_DEVICE_UNKNOWN,                   \
        VMX_HYPERCALL_FUNCTION_READ_PROC_CTLS, \
        METHOD_BUFFERED,                       \
        FILE_ANY_ACCESS)

typedef struct _HYPERCALL_RW_PROC_CTLS {
    HYPERCALL_HEADER header;
    IA32_VMX_PROCBASED_CTLS_REGISTER proc_ctls;
} HYPERCALL_RW_PROC_CTLS, *PHYPERCALL_RW_PROC_CTLS;

/*
 * IOCTL: IOCTL_HYPERCALL_WRITE_PROC_CTLS2
 * IOCTL: IOCTL_HYPERCALL_READ_PROC_CTLS2
 * Summary: Reads or updates the secondary processor-based VMCS controls.
 */
#define IOCTL_HYPERCALL_WRITE_PROC_CTLS2         \
    CTL_CODE(                                    \
        FILE_DEVICE_UNKNOWN,                     \
        VMX_HYPERCALL_FUNCTION_WRITE_PROC_CTLS2, \
        METHOD_BUFFERED,                         \
        FILE_ANY_ACCESS)

#define IOCTL_HYPERCALL_READ_PROC_CTLS2         \
    CTL_CODE(                                   \
        FILE_DEVICE_UNKNOWN,                    \
        VMX_HYPERCALL_FUNCTION_READ_PROC_CTLS2, \
        METHOD_BUFFERED,                        \
        FILE_ANY_ACCESS)

typedef struct _HYPERCALL_RW_PROC_CTLS2 {
    HYPERCALL_HEADER header;
    IA32_VMX_PROCBASED_CTLS2_REGISTER proc_ctls2;
} HYPERCALL_RW_PROC_CTLS2, *PHYPERCALL_RW_PROC_CTLS2;

/*
 * IOCTL: IOCTL_HYPERCALL_WRITE_PIN_CTLS
 * IOCTL: IOCTL_HYPERCALL_READ_PIN_CTLS
 * Summary: Reads or updates the pin-based VMCS controls.
 */
#define IOCTL_HYPERCALL_WRITE_PIN_CTLS         \
    CTL_CODE(                                  \
        FILE_DEVICE_UNKNOWN,                   \
        VMX_HYPERCALL_FUNCTION_WRITE_PIN_CTLS, \
        METHOD_BUFFERED,                       \
        FILE_ANY_ACCESS)

#define IOCTL_HYPERCALL_READ_PIN_CTLS         \
    CTL_CODE(                                 \
        FILE_DEVICE_UNKNOWN,                  \
        VMX_HYPERCALL_FUNCTION_READ_PIN_CTLS, \
        METHOD_BUFFERED,                      \
        FILE_ANY_ACCESS)

typedef struct _HYPERCALL_RW_PIN_CTLS {
    HYPERCALL_HEADER header;
    IA32_VMX_PINBASED_CTLS_REGISTER pin_ctls;
} HYPERCALL_RW_PIN_CTLS, *PHYPERCALL_RW_PIN_CTLS;

/*
 * IOCTL: IOCTL_HYPERCALL_WRITE_EXIT_CTLS
 * IOCTL: IOCTL_HYPERCALL_READ_EXIT_CTLS
 * Summary: Reads or updates the VMCS exit controls.
 */
#define IOCTL_HYPERCALL_WRITE_EXIT_CTLS         \
    CTL_CODE(                                   \
        FILE_DEVICE_UNKNOWN,                    \
        VMX_HYPERCALL_FUNCTION_WRITE_EXIT_CTLS, \
        METHOD_BUFFERED,                        \
        FILE_ANY_ACCESS)

#define IOCTL_HYPERCALL_READ_EXIT_CTLS         \
    CTL_CODE(                                  \
        FILE_DEVICE_UNKNOWN,                   \
        VMX_HYPERCALL_FUNCTION_READ_EXIT_CTLS, \
        METHOD_BUFFERED,                       \
        FILE_ANY_ACCESS)

typedef struct _HYPERCALL_RW_EXIT_CTLS {
    HYPERCALL_HEADER header;
    IA32_VMX_EXIT_CTLS_REGISTER exit_ctls;
} HYPERCALL_RW_EXIT_CTLS, *PHYPERCALL_RW_EXIT_CTLS;

/*
 * IOCTL: IOCTL_HYPERCALL_WRITE_ENTRY_CTLS
 * IOCTL: IOCTL_HYPERCALL_READ_ENTRY_CTLS
 * Summary: Reads or updates the VMCS entry controls.
 */
#define IOCTL_HYPERCALL_WRITE_ENTRY_CTLS         \
    CTL_CODE(                                    \
        FILE_DEVICE_UNKNOWN,                     \
        VMX_HYPERCALL_FUNCTION_WRITE_ENTRY_CTLS, \
        METHOD_BUFFERED,                         \
        FILE_ANY_ACCESS)

#define IOCTL_HYPERCALL_READ_ENTRY_CTLS         \
    CTL_CODE(                                   \
        FILE_DEVICE_UNKNOWN,                    \
        VMX_HYPERCALL_FUNCTION_READ_ENTRY_CTLS, \
        METHOD_BUFFERED,                        \
        FILE_ANY_ACCESS)

typedef struct _HYPERCALL_RW_ENTRY_CTLS {
    HYPERCALL_HEADER header;
    IA32_VMX_ENTRY_CTLS_REGISTER entry_ctls;
} HYPERCALL_RW_ENTRY_CTLS, *PHYPERCALL_RW_ENTRY_CTLS;

/*
 * IOCTL: IOCTL_HYPERCALL_WRITE_EXCEPTION_BITMAP
 * IOCTL: IOCTL_HYPERCALL_READ_EXCEPTION_BITMAP
 * Summary: Reads or updates the VMCS exception bitmap.
 */
#define IOCTL_HYPERCALL_WRITE_EXCEPTION_BITMAP         \
    CTL_CODE(                                          \
        FILE_DEVICE_UNKNOWN,                           \
        VMX_HYPERCALL_FUNCTION_WRITE_EXCEPTION_BITMAP, \
        METHOD_BUFFERED,                               \
        FILE_ANY_ACCESS)

#define IOCTL_HYPERCALL_READ_EXCEPTION_BITMAP         \
    CTL_CODE(                                         \
        FILE_DEVICE_UNKNOWN,                          \
        VMX_HYPERCALL_FUNCTION_READ_EXCEPTION_BITMAP, \
        METHOD_BUFFERED,                              \
        FILE_ANY_ACCESS)

typedef struct _HYPERCALL_RW_EXCEPTION_BITMAP {
    HYPERCALL_HEADER header;
    UINT32 exception_bitmap;
} HYPERCALL_RW_EXCEPTION_BITMAP, *PHYPERCALL_RW_EXCEPTION_BITMAP;

/*
 * IOCTL: IOCTL_HYPERCALL_WRITE_MSR_BITMAP
 * IOCTL: IOCTL_HYPERCALL_READ_MSR_BITMAP
 * Summary: Reads or updates the MSR bitmap physical address.
 */
#define IOCTL_HYPERCALL_WRITE_MSR_BITMAP         \
    CTL_CODE(                                    \
        FILE_DEVICE_UNKNOWN,                     \
        VMX_HYPERCALL_FUNCTION_WRITE_MSR_BITMAP, \
        METHOD_BUFFERED,                         \
        FILE_ANY_ACCESS)

#define IOCTL_HYPERCALL_READ_MSR_BITMAP         \
    CTL_CODE(                                   \
        FILE_DEVICE_UNKNOWN,                    \
        VMX_HYPERCALL_FUNCTION_READ_MSR_BITMAP, \
        METHOD_BUFFERED,                        \
        FILE_ANY_ACCESS)

typedef struct _HYPERCALL_RW_MSR_BITMAP {
    HYPERCALL_HEADER header;
    PUINT8 msr_bitmap[0x1000];
} HYPERCALL_RW_MSR_BITMAP, *PHYPERCALL_RW_MSR_BITMAP;

/* exported function */
UINT32 HvCliPing(VOID);

UINT32
HvCliTerminate(VOID);

UINT32
HvCliQueryStats(_Out_ PVCPU_STATS Stats);

#endif