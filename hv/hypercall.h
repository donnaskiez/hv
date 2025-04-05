#ifndef HYPERCALL_H
#define HYPERCALL_H

#include "common.h"

#include "vmx.h"

#define HVSTATUS_SUCCESS           0
#define HVSTATUS_FAILURE           1
#define HVSTATUS_NOT_HANDLED       2
#define HVSTATUS_INVALID_PARAMETER 3

typedef NTSTATUS HVSTATUS;

#define HV_SUCCESS(Status) ((Status) == HVSTATUS_SUCCESS)

/*
 * [63:56] Category (8 bits)
 * [47:0]  Function ID (48 bits)
 */

#define VMX_HYPERCALL_CATEGORY_CONTROL 0x01
#define VMX_HYPERCALL_CATEGORY_QUERY   0x02
#define VMX_HYPERCALL_CATEGORY_MISC    0xFF

#define DEFINE_HYPERCALL(category, function_id) \
    (((UINT64)(category) << 56) | ((UINT64)(function_id)))

/* hypercall IDs */
#define VMX_HYPERCALL_FUNCTION_TERMINATE   0
#define VMX_HYPERCALL_FUNCTION_PING        1
#define VMX_HYPERCALL_FUNCTION_QUERY_STATS 2

/* terminate VMX */
#define VMX_HYPERCALL_TERMINATE_VMX     \
    DEFINE_HYPERCALL(                   \
        VMX_HYPERCALL_CATEGORY_CONTROL, \
        VMX_HYPERCALL_FUNCTION_TERMINATE)

/* ping */
#define VMX_HYPERCALL_PING \
    DEFINE_HYPERCALL(VMX_HYPERCALL_CATEGORY_QUERY, VMX_HYPERCALL_FUNCTION_PING)

/* query stats */
#define VMX_HYPERCALL_QUERY_STATS     \
    DEFINE_HYPERCALL(                 \
        VMX_HYPERCALL_CATEGORY_QUERY, \
        VMX_HYPERCALL_FUNCTION_QUERY_STATS)

NTSTATUS
HvHypercallDispatch(
    _In_ PVCPU Vcpu,
    _In_ UINT64 HypercallId,
    _In_opt_ UINT64 OptionalParameter1,
    _In_opt_ UINT64 OptionalParameter2,
    _In_opt_ UINT64 OptionalParameter3);

#endif