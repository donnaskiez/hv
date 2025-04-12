#ifndef HYPERCALL_H
#define HYPERCALL_H

#include "common.h"

#include "vmx.h"

#define HV_SUCCESS(Status) ((Status) == HVSTATUS_SUCCESS)

/* ring -1 */

NTSTATUS
HvHypercallDispatch(
    _In_ PVCPU Vcpu,
    _In_ UINT64 HypercallId,
    _In_opt_ UINT64 OptionalParameter1,
    _In_opt_ UINT64 OptionalParameter2,
    _In_opt_ UINT64 OptionalParameter3);

NTSTATUS
HvHypercallInternalVmxTerminate();

/* ring 0 */

NTSTATUS
HvHypercallDispatchFromGuest(_In_ PIRP Irp, _In_ PIO_STACK_LOCATION Io);

#endif