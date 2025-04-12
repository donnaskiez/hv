#include <windows.h>
#include <stdio.h>
#include <stdint.h>

#define HVSTATUS_SUCCESS           0
#define HVSTATUS_FAILURE           1
#define HVSTATUS_NOT_HANDLED       2
#define HVSTATUS_INVALID_PARAMETER 3
#define HVSTATUS_INVALID_GUEST_CPL 4
#define HVSTATUS_BUFFER_TOO_SMALL  5

typedef ULONG HVSTATUS;

#define HV_SUCCESS(Status) ((Status) == HVSTATUS_SUCCESS)

#define VMX_HYPERCALL_FUNCTION_TERMINATE   0x800
#define VMX_HYPERCALL_FUNCTION_PING        0x801
#define VMX_HYPERCALL_FUNCTION_QUERY_STATS 0x802


#define VMX_HYPERCALL_GET_FUNCTION(Io) \
    (((Io)->Parameters.DeviceIoControl.IoControlCode >> 2) & 0xFFFFF)


#define IOCTL_HYPERCALL_TERMINATE_VMX     \
    CTL_CODE(                             \
        FILE_DEVICE_UNKNOWN,              \
        VMX_HYPERCALL_FUNCTION_TERMINATE, \
        METHOD_BUFFERED,                  \
        FILE_ANY_ACCESS)

#define IOCTL_HYPERCALL_PING         \
    CTL_CODE(                        \
        FILE_DEVICE_UNKNOWN,         \
        VMX_HYPERCALL_FUNCTION_PING, \
        METHOD_BUFFERED,             \
        FILE_ANY_ACCESS)


typedef struct _HYPERCALL_PING {
    UINT32 value;
} HYPERCALL_PING, *PHYPERCALL_PING;


#define IOCTL_HYPERCALL_QUERY_STATS         \
    CTL_CODE(                               \
        FILE_DEVICE_UNKNOWN,                \
        VMX_HYPERCALL_FUNCTION_QUERY_STATS, \
        METHOD_BUFFERED,                    \
        FILE_ANY_ACCESS)

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
    } hypercall;

} VCPU_STATS, *PVCPU_STATS;

typedef struct _HYPERCALL_QUERY_STATS {
    VCPU_STATS stats;
} HYPERCALL_QUERY_STATS, *PHYPERCALL_QUERY_STATS;

int
main(void)
{
    HANDLE device = CreateFileA(
        "\\\\.\\hv-link", // Replace with your actual device name
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (device == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to open device: %lu\n", GetLastError());
        return 1;
    }

    HYPERCALL_QUERY_STATS stats = {0};
    DWORD bytesReturned = 0;

    BOOL ok = DeviceIoControl(
        device,
        IOCTL_HYPERCALL_QUERY_STATS,
        NULL,
        0,
        &stats,
        sizeof(stats),
        &bytesReturned,
        NULL);

    if (!ok) {
        printf("[-] DeviceIoControl failed: %lu\n", GetLastError());
        CloseHandle(device);
        return 1;
    }

    // Print results
    printf("[+] VM Exit Count: %llu\n", stats.stats.exit_count);
    printf("    CPUID:            %llu\n", stats.stats.reasons.cpuid);
    printf("    INVD:             %llu\n", stats.stats.reasons.invd);
    printf("    VMCALL:           %llu\n", stats.stats.reasons.vmcall);
    printf("    MOV_CR:           %llu\n", stats.stats.reasons.mov_cr);
    printf("    WBINVD:           %llu\n", stats.stats.reasons.wbinvd);
    printf("    TPR_THRESHOLD:    %llu\n", stats.stats.reasons.tpr_threshold);
    printf(
        "    EXC/NMI:          %llu\n",
        stats.stats.reasons.exception_or_nmi);
    printf("    TRAP_FLAGS:       %llu\n", stats.stats.reasons.trap_flags);
    printf("    WRMSR:            %llu\n", stats.stats.reasons.wrmsr);
    printf("    RDMSR:            %llu\n", stats.stats.reasons.rdmsr);
    printf("    MOV_DR:           %llu\n", stats.stats.reasons.mov_dr);
    printf("    VIRTUAL_EOI:      %llu\n", stats.stats.reasons.virtualised_eoi);
    printf(
        "    PREEMPT_TIMER:    %llu\n",
        stats.stats.reasons.preemption_timer);

    printf("Hypercall Usage:\n");
    printf("    Ping:             %llu\n", stats.stats.hypercall.ping);
    printf("    Query Stats:      %llu\n", stats.stats.hypercall.query_stats);
    printf("    Terminate:        %llu\n", stats.stats.hypercall.terminate);

    CloseHandle(device);
    printf("\nPress Enter to exit...");
    getchar();
    return 0;
}
