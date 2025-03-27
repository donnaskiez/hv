#pragma once

#include <ntddk.h>
#include <wdf.h>
#include <wdm.h>

#define DEBUG_LOG(fmt, ...) \
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "hv-log: " fmt "\n", ##__VA_ARGS__)
#define DEBUG_ERROR(fmt, ...) \
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "hv-error: " fmt "\n", ##__VA_ARGS__)
#define DEBUG_LOG_ROOT(fmt, ...) \
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "[ROOT]: " fmt "\n", ##__VA_ARGS__)

#define POOL_TAG_VMM_STATE         'smmv'
#define POOL_TAG_DRIVER_STATE      'dsds'
#define POOL_TAG_VMM_STACK         'kats'
#define POOL_TAG_DPC_CONTEXT       'ccpd'
#define POOL_TAG_STATUS_ARRAY      'tats'
#define POOL_TAG_EPT_POINTER       'ptpe'
#define POOL_TAG_EPT_PML4          '4lmp'
#define POOL_TAG_EPT_PDPT          'tpdp'
#define POOL_TAG_EPT_PD            'dpdp'
#define POOL_TAG_EPT_PT            'tptp'
#define POOL_TAG_EPT_GUEST_VIRTUAL 'ivug'
#define POOL_TAG_VIRTUAL_APIC      'cipa'

#define STATIC static
#define VOID   void
#define INLINE inline
#define EXTERN extern

#define VMX_HYPERCALL_TERMINATE_VMX 0ull
#define VMX_HYPERCALL_PING          1ull

#define VMCS_HOST_SELECTOR_MASK 0xF8

#define CLEAR_CR3_RESERVED_BIT(value) ((value) & ~(1ull << 63))

#define VMX_HOST_STACK_SIZE 0x8000

#define VMX_STATUS_OK                         0
#define VMX_STATUS_OPERATION_FAILED           1
#define VMX_STATUS_OPERATION_FAILED_NO_STATUS 2

#define VMX_OK(x) x == VMX_STATUS_OK

#define ABSOLUTE(wait)       (wait)
#define RELATIVE(wait)       (-(wait))
#define NANOSECONDS(nanos)   (((signed __int64)(nanos)) / 100L)
#define MICROSECONDS(micros) (((signed __int64)(micros)) * NANOSECONDS(1000L))
#define MILLISECONDS(milli)  (((signed __int64)(milli)) * MICROSECONDS(1000L))
#define SECONDS(seconds)     (((signed __int64)(seconds)) * MILLISECONDS(1000L))

VOID
KeGenericCallDpc(_In_ PKDEFERRED_ROUTINE Routine, _In_opt_ PVOID Context);

LOGICAL
KeSignalCallDpcSynchronize(_In_ PVOID SystemArgument2);

VOID
KeSignalCallDpcDone(_In_ PVOID SystemArgument1);