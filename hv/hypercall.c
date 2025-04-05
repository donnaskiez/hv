#include "hypercall.h"

#include "log.h"
#include "vmx.h"
#include "vmcs.h"

#define VMX_HYPERCALL_PING_RESPONSE 0x4345345

#define HV_HYPERCALL_INIT_ARGS(ptr, id, out_buf, out_buf_len, placeholder) \
    do {                                                                   \
        (ptr)->hypercall_status = HVSTATUS_NOT_HANDLED;                    \
        (ptr)->hypercall_id = (id);                                        \
        (ptr)->hypercall_out_buf = (out_buf);                              \
        (ptr)->hypercall_out_buf_len = (out_buf_len);                      \
        (ptr)->hypercall_placeholder = (placeholder);                      \
    } while (0)

typedef struct _HYPERCALL_ARGS {
    UINT64 hypercall_status;      /* rax (return value) */
    UINT64 hypercall_id;          /* rcx */
    PUINT8 hypercall_out_buf;     /* rdx */
    UINT64 hypercall_out_buf_len; /* r8 */
    UINT64 hypercall_placeholder; /* r9 */
} HYPERCALL_ARGS, *PHYPERCALL_ARGS;

FORCEINLINE
STATIC
BOOLEAN
HvHypercallIsOutBufValid(_In_ PHYPERCALL_ARGS Args, _In_ UINT32 RequiredLength)
{
    return Args->hypercall_out_buf_len >= RequiredLength;
}

FORCEINLINE
STATIC
BOOLEAN
HvHypercallIsLikelyUserPointer(UINT64 address)
{
    return address < 0x0000800000000000ULL;
}

FORCEINLINE
STATIC
BOOLEAN
HvHypercallIsLikelyKernelPointer(UINT64 address)
{
    return address >= 0xFFFF800000000000ULL;
}

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
    /* ping returns a UINT64 magic value */
    if (!HvHypercallIsOutBufValid(Args, sizeof(UINT64))) {
        Args->hypercall_status = HVSTATUS_INVALID_PARAMETER;
        return;
    }

    *(PUINT64)Args->hypercall_out_buf = VMX_HYPERCALL_PING_RESPONSE;
}

STATIC HVSTATUS
HvHypercallValidateArgs(_In_ PVCPU Vcpu, _In_ PHYPERCALL_ARGS Args)
{
    UINT16 cpl = HvVmcsGuestGetProtectionLevel();

    if (Args->hypercall_out_buf && !Args->hypercall_out_buf_len)
        return HVSTATUS_INVALID_PARAMETER;

    if (!Args->hypercall_out_buf && Args->hypercall_out_buf_len)
        return HVSTATUS_INVALID_PARAMETER;

    if (Args->hypercall_out_buf) {
        if (cpl == HV_GUEST_CPL_KERNEL &&
            !HvHypercallIsLikelyKernelPointer(Args->hypercall_out_buf)) {
            return HVSTATUS_INVALID_PARAMETER;
        }
        else if (
            cpl == HV_GUEST_CPL_USER &&
            !HvHypercallIsLikelyUserPointer(Args->hypercall_out_buf)) {
            return HVSTATUS_INVALID_PARAMETER;
        }
    }

    return HVSTATUS_SUCCESS;
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
        args.hypercall_out_buf,
        args.hypercall_out_buf_len,
        args.hypercall_placeholder);

    status = HvHypercallValidateArgs(Vcpu, &args);
    if (!HV_SUCCESS(status))
        return STATUS_INVALID_PARAMETER;

    switch (HypercallId) {
    case VMX_HYPERCALL_TERMINATE_VMX: HvHypercallHandleTerminate(&args); break;
    case VMX_HYPERCALL_PING: HvHypercallHandlePing(&args); break;
    default: break;
    }

    return args.hypercall_status == HVSTATUS_SUCCESS ? STATUS_SUCCESS
                                                     : STATUS_UNSUCCESSFUL;
}