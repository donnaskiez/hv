#include "hypercall.h"

#include "log.h"
#include "vmx.h"
#include "vmcs.h"

#include <intrin.h>

/*
 * Common code
 */

#define HVSTATUS_SUCCESS           0
#define HVSTATUS_FAILURE           1
#define HVSTATUS_NOT_HANDLED       2
#define HVSTATUS_INVALID_PARAMETER 3
#define HVSTATUS_INVALID_GUEST_CPL 4
#define HVSTATUS_BUFFER_TOO_SMALL  5

typedef ULONG HVSTATUS;

/*
 * Extracts the hypercall "Function" bits from a 32-bit IOCTL code.
 * We shift right by 2 to remove the METHOD bits (bits [1..0]),
 * then mask off as many bits as needed. Here we use 0xFFF (12 bits)
 * to match valid function field size in CTL_CODE macros.
 */
#define VMX_HYPERCALL_GET_FUNCTION(Io) \
    (((Io)->Parameters.DeviceIoControl.IoControlCode >> 2) & 0xFFF)

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

typedef struct _HYPERCALL_PING {
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
    UINT64 msr_bitmap;
} HYPERCALL_RW_MSR_BITMAP, *PHYPERCALL_RW_MSR_BITMAP;

/*
 * IOCTL: IOCTL_HYPERCALL_WRITE_MSR_BITMAP
 * Summary: Updates the MSR bitmap pointer in the VMCS.
 */
#define IOCTL_HYPERCALL_WRITE_MSR_BITMAP         \
    CTL_CODE(                                    \
        FILE_DEVICE_UNKNOWN,                     \
        VMX_HYPERCALL_FUNCTION_WRITE_MSR_BITMAP, \
        METHOD_BUFFERED,                         \
        FILE_ANY_ACCESS)

typedef struct _HYPERCALL_WRITE_MSR_BITMAP {
    UINT64 msr_bitmap;
} HYPERCALL_WRITE_MSR_BITMAP, *PHYPERCALL_WRITE_MSR_BITMAP;

STATIC
UINT32
HvHypercallGetRequiredInOutBufSize(_In_ UINT32 hypercall_id)
{
    switch (hypercall_id) {
    case VMX_HYPERCALL_FUNCTION_TERMINATE: return 0;
    case VMX_HYPERCALL_FUNCTION_PING: return sizeof(HYPERCALL_PING);
    case VMX_HYPERCALL_FUNCTION_QUERY_STATS:
        return sizeof(HYPERCALL_QUERY_STATS);
    case VMX_HYPERCALL_FUNCTION_READ_PROC_CTLS:
        return sizeof(HYPERCALL_RW_PROC_CTLS);
    case VMX_HYPERCALL_FUNCTION_READ_PROC_CTLS2:
        return sizeof(HYPERCALL_RW_PROC_CTLS2);
    case VMX_HYPERCALL_FUNCTION_READ_PIN_CTLS:
        return sizeof(HYPERCALL_RW_PIN_CTLS);
    case VMX_HYPERCALL_FUNCTION_READ_EXIT_CTLS:
        return sizeof(HYPERCALL_RW_EXIT_CTLS);
    case VMX_HYPERCALL_FUNCTION_READ_ENTRY_CTLS:
        return sizeof(HYPERCALL_RW_ENTRY_CTLS);
    case VMX_HYPERCALL_FUNCTION_READ_EXCEPTION_BITMAP:
        return sizeof(HYPERCALL_RW_EXCEPTION_BITMAP);
    case VMX_HYPERCALL_FUNCTION_READ_MSR_BITMAP:
        return sizeof(HYPERCALL_RW_MSR_BITMAP);
    default: return ULONG_MAX;
    }
}

/*
 * RING -1 (vmm) Hypercall dispatch functions
 */

#define HV_HYPERCALL_INIT_ARGS(ptr, id, buf, buf_len, placeholder) \
    do {                                                           \
        (ptr)->hypercall_status = HVSTATUS_NOT_HANDLED;            \
        (ptr)->hypercall_id = (id);                                \
        (ptr)->hypercall_buf = (buf);                              \
        (ptr)->hypercall_buf_len = (buf_len);                      \
        (ptr)->hypercall_placeholder = (placeholder);              \
    } while (0)

typedef struct _HYPERCALL_ARGS {
    UINT64 hypercall_status;      /* rax (return value) */
    UINT64 hypercall_id;          /* rcx */
    PUINT8 hypercall_buf;         /* rdx */
    UINT64 hypercall_buf_len;     /* r8 */
    UINT64 hypercall_placeholder; /* r9 */
} HYPERCALL_ARGS, *PHYPERCALL_ARGS;

FORCEINLINE
STATIC
VOID
HvHypercallHandleTerminate(_In_ PHYPERCALL_ARGS Args)
{
    InterlockedExchange(&HvVmxGetVcpu()->exit_state.exit_vmx, TRUE);
    Args->hypercall_status = HVSTATUS_SUCCESS;
}

FORCEINLINE
STATIC
VOID
HvHypercallHandlePing(_In_ PHYPERCALL_ARGS Args)
{
    PVCPU vcpu = HvVmxGetVcpu();

    HvVmxIncrementSequenceNumber(vcpu);

    RtlCopyMemory(
        Args->hypercall_buf,
        &vcpu->sequence_number,
        Args->hypercall_buf_len);

    Args->hypercall_status = HVSTATUS_SUCCESS;
}

/*
 * From the perspective of the vmm, the hypercall on returns the stats for the
 * current VCPU. This significantly reduces complexity and prevents the need to
 * thrash each VCPUs cache, all work combining the stats is done from the kernel
 * and passed back to user mode.
 */
FORCEINLINE
STATIC
VOID
HvHypercallHandleQueryStats(_In_ PHYPERCALL_ARGS Args)
{
    RtlCopyMemory(
        Args->hypercall_buf,
        &HvVmxGetVcpu()->stats,
        Args->hypercall_buf_len);

    Args->hypercall_status = HVSTATUS_SUCCESS;
}

/* Firstly it will update the current VCPUs (i.e the one executing) internal
 * structure and then write that new structure to the VMCS of said vcpu. Once
 * thats done, it will propagate the update to every other vcpu's pend_updates
 * and set the flag of the structure that needs to be updated. */
FORCEINLINE
STATIC
VOID
HvHypercallHandleVmcsWrite(_In_ PHYPERCALL_ARGS Args)
{
    PVCPU vcpu = HvVmxGetVcpu();
    UINT32 update = 0;

    switch (Args->hypercall_id) {
    case VMX_HYPERCALL_FUNCTION_WRITE_PROC_CTLS: {
        PHYPERCALL_RW_PROC_CTLS input =
            (PHYPERCALL_RW_PROC_CTLS)Args->hypercall_buf;
        vcpu->proc_ctls.AsUInt = input->proc_ctls.AsUInt;
        HvVmcsWritePrimaryProcessorControls(vcpu);
        update = HV_VCPU_PENDING_PROC_CTLS_UPDATE;
        break;
    }
    case VMX_HYPERCALL_FUNCTION_WRITE_PROC_CTLS2: {
        PHYPERCALL_RW_PROC_CTLS2 input =
            (PHYPERCALL_RW_PROC_CTLS2)Args->hypercall_buf;
        vcpu->proc_ctls2.AsUInt = input->proc_ctls2.AsUInt;
        HvVmcsWriteSecondaryProcessControls(vcpu);
        update = HV_VCPU_PENDING_PROC_CTLS2_UPDATE;
        break;
    }
    case VMX_HYPERCALL_FUNCTION_WRITE_PIN_CTLS: {
        PHYPERCALL_RW_PIN_CTLS input =
            (PHYPERCALL_RW_PIN_CTLS)Args->hypercall_buf;
        vcpu->pin_ctls.AsUInt = input->pin_ctls.AsUInt;
        HvVmcsWritePinBasedControls(vcpu);
        update = HV_VCPU_PENDING_PIN_CTLS_UPDATE;
        break;
    }
    case VMX_HYPERCALL_FUNCTION_WRITE_EXIT_CTLS: {
        PHYPERCALL_RW_EXIT_CTLS input =
            (PHYPERCALL_RW_EXIT_CTLS)Args->hypercall_buf;
        vcpu->exit_ctls.AsUInt = input->exit_ctls.AsUInt;
        HvVmcsWriteExitControls(vcpu);
        update = HV_VCPU_PENDING_EXIT_CTLS_UPDATE;
        break;
    }
    case VMX_HYPERCALL_FUNCTION_WRITE_ENTRY_CTLS: {
        PHYPERCALL_RW_ENTRY_CTLS input =
            (PHYPERCALL_RW_ENTRY_CTLS)Args->hypercall_buf;
        vcpu->entry_ctls.AsUInt = input->entry_ctls.AsUInt;
        HvVmcsWriteEntryControls(vcpu);
        update = HV_VCPU_PENDING_ENTRY_CTLS_UPDATE;
        break;
    }
    case VMX_HYPERCALL_FUNCTION_WRITE_EXCEPTION_BITMAP: {
        PHYPERCALL_RW_EXCEPTION_BITMAP input =
            (PHYPERCALL_RW_EXCEPTION_BITMAP)Args->hypercall_buf;
        vcpu->exception_bitmap = input->exception_bitmap;
        HvVmcsWriteExceptionBitmap(vcpu);
        update = HV_VCPU_PENDING_EXCEPTION_BITMAP_UPDATE;
        break;
    }
    case VMX_HYPERCALL_FUNCTION_WRITE_MSR_BITMAP: {
        PHYPERCALL_RW_MSR_BITMAP input =
            (PHYPERCALL_RW_MSR_BITMAP)Args->hypercall_buf;
        vcpu->msr_bitmap_pa = (PMSR_BITMAP)(UINT_PTR)input->msr_bitmap;
        HvVmcsWriteMsrBitmap(vcpu);
        update = HV_VCPU_PENDING_MSR_BITMAP_UPDATE;
        break;
    }
    default: {
        Args->hypercall_status = HVSTATUS_INVALID_PARAMETER;
        return;
    }
    }

    HvVmcsPropagateUpdate(vcpu, update);
    Args->hypercall_status = HVSTATUS_SUCCESS;
}

FORCEINLINE
STATIC
VOID
HvHypercallHandleVmcsRead(_In_ PHYPERCALL_ARGS Args)
{
    PVCPU vcpu = HvVmxGetVcpu();

    switch (Args->hypercall_id) {
    case VMX_HYPERCALL_FUNCTION_READ_PROC_CTLS: {
        PHYPERCALL_RW_PROC_CTLS output =
            (PHYPERCALL_RW_PROC_CTLS)Args->hypercall_buf;
        output->proc_ctls.AsUInt = vcpu->proc_ctls.AsUInt;
        break;
    }
    case VMX_HYPERCALL_FUNCTION_READ_PROC_CTLS2: {
        PHYPERCALL_RW_PROC_CTLS2 output =
            (PHYPERCALL_RW_PROC_CTLS2)Args->hypercall_buf;
        output->proc_ctls2.AsUInt = vcpu->proc_ctls2.AsUInt;
        break;
    }
    case VMX_HYPERCALL_FUNCTION_READ_PIN_CTLS: {
        PHYPERCALL_RW_PIN_CTLS output =
            (PHYPERCALL_RW_PIN_CTLS)Args->hypercall_buf;
        output->pin_ctls.AsUInt = vcpu->pin_ctls.AsUInt;
        break;
    }
    case VMX_HYPERCALL_FUNCTION_READ_EXIT_CTLS: {
        PHYPERCALL_RW_EXIT_CTLS output =
            (PHYPERCALL_RW_EXIT_CTLS)Args->hypercall_buf;
        output->exit_ctls.AsUInt = vcpu->exit_ctls.AsUInt;
        break;
    }
    case VMX_HYPERCALL_FUNCTION_READ_ENTRY_CTLS: {
        PHYPERCALL_RW_ENTRY_CTLS output =
            (PHYPERCALL_RW_ENTRY_CTLS)Args->hypercall_buf;
        output->entry_ctls.AsUInt = vcpu->entry_ctls.AsUInt;
        break;
    }
    case VMX_HYPERCALL_FUNCTION_READ_EXCEPTION_BITMAP: {
        PHYPERCALL_RW_EXCEPTION_BITMAP output =
            (PHYPERCALL_RW_EXCEPTION_BITMAP)Args->hypercall_buf;
        output->exception_bitmap = vcpu->exception_bitmap;
        break;
    }
    case VMX_HYPERCALL_FUNCTION_READ_MSR_BITMAP: {
        PHYPERCALL_RW_MSR_BITMAP output =
            (PHYPERCALL_RW_MSR_BITMAP)Args->hypercall_buf;
        output->msr_bitmap = (UINT64)(UINT_PTR)vcpu->msr_bitmap_pa;
        break;
    }
    default: {
        Args->hypercall_status = HVSTATUS_INVALID_PARAMETER;
        return;
    }
    }

    Args->hypercall_status = HVSTATUS_SUCCESS;
}

STATIC
HVSTATUS
HvHypercallValidateArgs(_In_ PVCPU Vcpu, _In_ PHYPERCALL_ARGS Args)
{
    UINT16 cpl = HvVmcsGuestGetProtectionLevel();

    if (cpl != HV_GUEST_CPL_KERNEL)
        return HVSTATUS_INVALID_GUEST_CPL;

    if (Args->hypercall_buf && !Args->hypercall_buf_len)
        return HVSTATUS_INVALID_PARAMETER;

    if (!Args->hypercall_buf && Args->hypercall_buf_len)
        return HVSTATUS_INVALID_PARAMETER;

    return HVSTATUS_SUCCESS;
}

STATIC
HVSTATUS
HvHypercallValidateInOutBufSize(_In_ PHYPERCALL_ARGS Args)
{
    UINT32 req_size =
        HvHypercallGetRequiredInOutBufSize((UINT32)Args->hypercall_id);

    if (req_size == ULONG_MAX)
        return HVSTATUS_INVALID_PARAMETER;

    return Args->hypercall_buf_len >= req_size ? HVSTATUS_SUCCESS
                                               : HVSTATUS_BUFFER_TOO_SMALL;
}

STATIC
VOID
HvHypercallIncrementStats(_In_ UINT64 HypercallId)
{
    PVCPU vcpu = HvVmxGetVcpu();

    switch (HypercallId) {
    case VMX_HYPERCALL_FUNCTION_TERMINATE:
        vcpu->stats.hypercall.terminate++;
        break;
    case VMX_HYPERCALL_FUNCTION_PING: vcpu->stats.hypercall.ping++; break;
    case VMX_HYPERCALL_FUNCTION_QUERY_STATS:
        vcpu->stats.hypercall.query_stats++;
        break;
    case VMX_HYPERCALL_FUNCTION_WRITE_PROC_CTLS:
        vcpu->stats.hypercall.write_proc_ctls++;
        break;
    case VMX_HYPERCALL_FUNCTION_WRITE_PROC_CTLS2:
        vcpu->stats.hypercall.write_proc_ctls2++;
        break;
    case VMX_HYPERCALL_FUNCTION_WRITE_PIN_CTLS:
        vcpu->stats.hypercall.write_pin_ctls++;
        break;
    case VMX_HYPERCALL_FUNCTION_WRITE_EXIT_CTLS:
        vcpu->stats.hypercall.write_exit_ctls++;
        break;
    case VMX_HYPERCALL_FUNCTION_WRITE_ENTRY_CTLS:
        vcpu->stats.hypercall.write_entry_ctls++;
        break;
    case VMX_HYPERCALL_FUNCTION_WRITE_EXCEPTION_BITMAP:
        vcpu->stats.hypercall.write_exception_bitmap++;
        break;
    case VMX_HYPERCALL_FUNCTION_WRITE_MSR_BITMAP:
        vcpu->stats.hypercall.write_msr_bitmap++;
        break;
    case VMX_HYPERCALL_FUNCTION_READ_PROC_CTLS:
        vcpu->stats.hypercall.read_proc_ctls++;
        break;
    case VMX_HYPERCALL_FUNCTION_READ_PROC_CTLS2:
        vcpu->stats.hypercall.read_proc_ctls2++;
        break;
    case VMX_HYPERCALL_FUNCTION_READ_PIN_CTLS:
        vcpu->stats.hypercall.read_pin_ctls++;
        break;
    case VMX_HYPERCALL_FUNCTION_READ_EXIT_CTLS:
        vcpu->stats.hypercall.read_exit_ctls++;
        break;
    case VMX_HYPERCALL_FUNCTION_READ_ENTRY_CTLS:
        vcpu->stats.hypercall.read_entry_ctls++;
        break;
    case VMX_HYPERCALL_FUNCTION_READ_EXCEPTION_BITMAP:
        vcpu->stats.hypercall.read_exception_bitmap++;
        break;
    case VMX_HYPERCALL_FUNCTION_READ_MSR_BITMAP:
        vcpu->stats.hypercall.read_msr_bitmap++;
        break;
    default: break;
    }
}

NTSTATUS
HvHypercallDispatch(
    _In_ PVCPU Vcpu,
    _In_ UINT64 HypercallId,
    _In_opt_ UINT64 OptionalParameter1,
    _In_opt_ UINT64 OptionalParameter2,
    _In_opt_ UINT64 OptionalParameter3)
{
    HVSTATUS status = HVSTATUS_FAILURE;
    HYPERCALL_ARGS args = {0};

    HV_HYPERCALL_INIT_ARGS(
        &args,
        HypercallId,
        OptionalParameter1,
        OptionalParameter2,
        OptionalParameter3);

    HIGH_IRQL_LOG_SAFE(
        "Handling hypercall id: %llx, arg1: %llx, arg2: %llx, arg3: %llx",
        HypercallId,
        args.hypercall_buf,
        args.hypercall_buf_len,
        args.hypercall_placeholder);

    HvHypercallIncrementStats(HypercallId);

    status = HvHypercallValidateArgs(Vcpu, &args);
    if (!HV_SUCCESS(status))
        return HVSTATUS_INVALID_PARAMETER;

    status = HvHypercallValidateInOutBufSize(&args);
    if (!HV_SUCCESS(status))
        return HVSTATUS_BUFFER_TOO_SMALL;

    switch (HypercallId) {
    case VMX_HYPERCALL_FUNCTION_TERMINATE:
        HvHypercallHandleTerminate(&args);
        break;
    case VMX_HYPERCALL_FUNCTION_PING: {
        HvHypercallHandlePing(&args);
        break;
    }
    case VMX_HYPERCALL_FUNCTION_QUERY_STATS: {
        HvHypercallHandleQueryStats(&args);
        break;
    }
    case VMX_HYPERCALL_FUNCTION_WRITE_PROC_CTLS:
    case VMX_HYPERCALL_FUNCTION_WRITE_PROC_CTLS2:
    case VMX_HYPERCALL_FUNCTION_WRITE_PIN_CTLS:
    case VMX_HYPERCALL_FUNCTION_WRITE_EXIT_CTLS:
    case VMX_HYPERCALL_FUNCTION_WRITE_ENTRY_CTLS:
    case VMX_HYPERCALL_FUNCTION_WRITE_EXCEPTION_BITMAP:
    case VMX_HYPERCALL_FUNCTION_WRITE_MSR_BITMAP: {
        HvHypercallHandleVmcsWrite(&args);
        break;
    }
    case VMX_HYPERCALL_FUNCTION_READ_PROC_CTLS:
    case VMX_HYPERCALL_FUNCTION_READ_PROC_CTLS2:
    case VMX_HYPERCALL_FUNCTION_READ_PIN_CTLS:
    case VMX_HYPERCALL_FUNCTION_READ_EXIT_CTLS:
    case VMX_HYPERCALL_FUNCTION_READ_ENTRY_CTLS:
    case VMX_HYPERCALL_FUNCTION_READ_EXCEPTION_BITMAP:
    case VMX_HYPERCALL_FUNCTION_READ_MSR_BITMAP: {
        HvHypercallHandleVmcsRead(&args);
        break;
    }
    default: {
        return HVSTATUS_INVALID_PARAMETER;
    }
    }

    return args.hypercall_status;
}

/*
 * RING 0 Hypercall dispatch functions
 */

NTSTATUS
HvHypercallInternalVmxTerminate()
{
    return HvVmxExecuteVmCall(VMX_HYPERCALL_FUNCTION_TERMINATE, 0, 0, 0);
}

STATIC
NTSTATUS
HvHypercallValidateIrpBuffer(_In_ PIRP Irp, _In_ PIO_STACK_LOCATION Io)
{
    UINT32 hypercall_id = VMX_HYPERCALL_GET_FUNCTION(Io);
    UINT32 req_size = HvHypercallGetRequiredInOutBufSize(hypercall_id);
    UINT32 buf_size = Io->Parameters.DeviceIoControl.OutputBufferLength;

    if (req_size == ULONG_MAX)
        return STATUS_INVALID_PARAMETER;

    return buf_size >= req_size ? STATUS_SUCCESS : STATUS_INVALID_BUFFER_SIZE;
}

/* Ensure we have a METHOD_BUFFERED IOCTL. We want to let the kernel handle the
 * locking of the buffer + return to user mode. */
STATIC
NTSTATUS
HvHypercallValidateIrpBufferProtocol(_In_ PIO_STACK_LOCATION Io)
{
    return METHOD_FROM_CTL_CODE(Io->Parameters.DeviceIoControl.IoControlCode) ==
                   METHOD_BUFFERED
               ? STATUS_SUCCESS
               : STATUS_INVALID_PARAMETER;
}

STATIC
VOID
HvHypercallUpdateRetStats(
    _In_ PHYPERCALL_QUERY_STATS Ret,
    _In_ PHYPERCALL_QUERY_STATS Local)
{
    PVCPU_STATS ret = &Ret->stats;
    PVCPU_STATS local = &Local->stats;

    ret->exit_count += local->exit_count;

    /* exit reason */
    ret->reasons.cpuid += local->reasons.cpuid;
    ret->reasons.invd += local->reasons.invd;
    ret->reasons.vmcall += local->reasons.vmcall;
    ret->reasons.mov_cr += local->reasons.mov_cr;
    ret->reasons.wbinvd += local->reasons.wbinvd;
    ret->reasons.tpr_threshold += local->reasons.tpr_threshold;
    ret->reasons.exception_or_nmi += local->reasons.exception_or_nmi;
    ret->reasons.trap_flags += local->reasons.trap_flags;
    ret->reasons.wrmsr += local->reasons.wrmsr;
    ret->reasons.rdmsr += local->reasons.rdmsr;
    ret->reasons.mov_dr += local->reasons.mov_dr;
    ret->reasons.virtualised_eoi += local->reasons.virtualised_eoi;
    ret->reasons.preemption_timer += local->reasons.preemption_timer;

    /* hypercall stats */
    ret->hypercall.ping += local->hypercall.ping;
    ret->hypercall.query_stats += local->hypercall.query_stats;
    ret->hypercall.terminate += local->hypercall.terminate;
}

STATIC
NTSTATUS
HvHypercallDispatchQueryStats(_In_ PIRP Irp, _In_ PIO_STACK_LOCATION Io)
{
    UINT32 index = 0;
    NTSTATUS status = STATUS_SUCCESS;
    GROUP_AFFINITY old_affinity = {0};
    GROUP_AFFINITY target_affinity = {0};
    PROCESSOR_NUMBER proc_num = {0};
    PROCESSOR_NUMBER current_proc = {0};
    HYPERCALL_QUERY_STATS core_stats = {0};
    PHYPERCALL_QUERY_STATS ret_stats = Irp->AssociatedIrp.SystemBuffer;

    RtlZeroMemory(ret_stats, sizeof(*ret_stats));

    for (index = 0; index < KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
         index++) {
        KeGetProcessorNumberFromIndex(index, &proc_num);
        target_affinity.Group = proc_num.Group;
        target_affinity.Mask = 1ull << proc_num.Number;
        KeSetSystemGroupAffinityThread(&target_affinity, &old_affinity);

        /* sanity check */
        KeGetCurrentProcessorNumberEx(&current_proc);
        if (current_proc.Group != proc_num.Group ||
            current_proc.Number != proc_num.Number) {
            KeRevertToUserGroupAffinityThread(&old_affinity);
            DEBUG_ERROR(
                "Thread did not switch to processor %lu (Group %u, Number %u)",
                index,
                proc_num.Group,
                proc_num.Number);
            return STATUS_UNSUCCESSFUL;
        }

        RtlZeroMemory(&core_stats, sizeof(core_stats));

        status = HvVmxExecuteVmCall(
            VMX_HYPERCALL_FUNCTION_QUERY_STATS,
            &core_stats,
            sizeof(core_stats),
            0);

        KeRevertToUserGroupAffinityThread(&old_affinity);

        if (!NT_SUCCESS(status)) {
            DEBUG_ERROR(
                "HvVmxExecuteVmCall failed on core %lu: %lx",
                index,
                status);
            return status;
        }

        HvHypercallUpdateRetStats(ret_stats, &core_stats);
    }

    Irp->IoStatus.Information = sizeof(*ret_stats);
    return STATUS_SUCCESS;
}

/* For some hypercalls such as ping and terminate they dont require any further
 * functionality hence can use this simple passthrough wrapper. */
STATIC
NTSTATUS
HvHypercallDispatchSimple(
    _In_ UINT32 HypercallId,
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION Io)
{
    return HvVmxExecuteVmCall(
        HypercallId,
        Irp->AssociatedIrp.SystemBuffer,
        Io->Parameters.DeviceIoControl.OutputBufferLength,
        0);
}

/* IOCTL handler that dispatches the hypercall to the vmm */
NTSTATUS
HvHypercallDispatchFromGuest(_In_ PIRP Irp, _In_ PIO_STACK_LOCATION Io)
{
    PMDL mdl = NULL;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    UINT32 hypercall_id = VMX_HYPERCALL_GET_FUNCTION(Io);

    DEBUG_LOG("Dispatching Hypercall: %lx", hypercall_id);

    status = HvHypercallValidateIrpBuffer(Irp, Io);
    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR("HvHypercallValidateIrpBuffer: %lx", status);
        return status;
    }

    /* All IOCTLs passed at this point have been validated as METHOD_BUFFERED,
     * meaing we dont need to probe and lock any buffers.*/
    status = HvHypercallValidateIrpBufferProtocol(Io);
    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR("HvHypercallValidateIrpBufferProtocol failed: %lx", status);
        return status;
    }

    /*
     * For most hypercalls we simply validate the arguments and pass through the
     * buffer directly to the hypervisor since the hypercall is independent of
     * the core it gets executed on. Any hypercall that requires further setup
     * should not use the DispatchSimple function.
     */
    switch (hypercall_id) {
    case VMX_HYPERCALL_FUNCTION_TERMINATE:
    case VMX_HYPERCALL_FUNCTION_PING:
    case VMX_HYPERCALL_FUNCTION_WRITE_PROC_CTLS:
    case VMX_HYPERCALL_FUNCTION_WRITE_PROC_CTLS2:
    case VMX_HYPERCALL_FUNCTION_WRITE_PIN_CTLS:
    case VMX_HYPERCALL_FUNCTION_WRITE_EXIT_CTLS:
    case VMX_HYPERCALL_FUNCTION_WRITE_ENTRY_CTLS:
    case VMX_HYPERCALL_FUNCTION_WRITE_EXCEPTION_BITMAP:
    case VMX_HYPERCALL_FUNCTION_WRITE_MSR_BITMAP:
    case VMX_HYPERCALL_FUNCTION_READ_PROC_CTLS:
    case VMX_HYPERCALL_FUNCTION_READ_PROC_CTLS2:
    case VMX_HYPERCALL_FUNCTION_READ_PIN_CTLS:
    case VMX_HYPERCALL_FUNCTION_READ_EXIT_CTLS:
    case VMX_HYPERCALL_FUNCTION_READ_ENTRY_CTLS:
    case VMX_HYPERCALL_FUNCTION_READ_EXCEPTION_BITMAP:
    case VMX_HYPERCALL_FUNCTION_READ_MSR_BITMAP:
        status = HvHypercallDispatchSimple(hypercall_id, Irp, Io);
        break;
    case VMX_HYPERCALL_FUNCTION_QUERY_STATS:
        status = HvHypercallDispatchQueryStats(Irp, Io);
        break;
    default: status = STATUS_INVALID_PARAMETER;
    }

    return status;
}