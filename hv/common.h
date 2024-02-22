#pragma once

#include <ntddk.h>
#include <wdf.h>
#include <wdm.h>

#define DEBUG_LOG(fmt, ...)   DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "[+] " fmt "\n", ##__VA_ARGS__)
#define DEBUG_ERROR(fmt, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "[-] " fmt "\n", ##__VA_ARGS__)

#define POOLTAG 'pool'

#define STATIC static
#define VOID   void
#define INLINE inline
#define EXTERN extern

typedef union _MSR
{
        struct
        {
                ULONG Low;
                ULONG High;
        };

        ULONG64 Content;
} MSR, *PMSR;

typedef struct _GUEST_CONTEXT
{
        M128A  Xmm0;
        M128A  Xmm1;
        M128A  Xmm2;
        M128A  Xmm3;
        M128A  Xmm4;
        M128A  Xmm5;
        UINT64 rax;
        UINT64 rcx;
        UINT64 rdx;
        UINT64 rbx;
        UINT64 rsp;
        UINT64 rbp;
        UINT64 rsi;
        UINT64 rdi;
        UINT64 r8;
        UINT64 r9;
        UINT64 r10;
        UINT64 r11;
        UINT64 r12;
        UINT64 r13;
        UINT64 r14;
        UINT64 r15;
        UINT32 eflags;
} GUEST_CONTEXT, *PGUEST_CONTEXT;

#define VMX_HYPERCALL_TERMINATE_VMX 0ull
#define VMX_HYPERCALL_PING 1ull

#define VMCS_HOST_SELECTOR_MASK 0xF8

#define CLEAR_CR3_RESERVED_BIT(value) ((value) & ~(1ull << 63))

#define VMX_HOST_STACK_SIZE 0x8000

#define VMX_STATUS_OK 0
#define VMX_STATUS_OPERATION_FAILED 1
#define VMX_STATUS_OPERATION_FAILED_NO_STATUS 2

#define VMX_OK(x) x == VMX_STATUS_OK

VOID
KeGenericCallDpc(_In_ PKDEFERRED_ROUTINE Routine, _In_opt_ PVOID Context);

LOGICAL
KeSignalCallDpcSynchronize(_In_ PVOID SystemArgument2);

VOID
KeSignalCallDpcDone(_In_ PVOID SystemArgument1);