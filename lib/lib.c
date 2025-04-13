#include <windows.h>
#include <stdio.h>
#include <stdint.h>

#include "lib.h"

UINT32
HvCliPing(VOID)
{
    HANDLE device_handle = INVALID_HANDLE_VALUE;
    BOOL result = FALSE;
    DWORD bytes_returned = 0;
    HYPERCALL_PING ping_data = {0};

    device_handle = CreateFileA(
        "\\\\.\\hv-link",
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (device_handle == INVALID_HANDLE_VALUE) {
        return HVSTATUS_DEVICE_OPEN_FAIL;
    }

    result = DeviceIoControl(
        device_handle,
        IOCTL_HYPERCALL_PING,
        &ping_data,
        sizeof(ping_data),
        &ping_data,
        sizeof(ping_data),
        &bytes_returned,
        NULL);

    CloseHandle(device_handle);

    return ping_data.value == HV_VMX_PING_VALUE ? HVSTATUS_SUCCESS
                                                : HVSTATUS_INVALID_PING_VALUE;
}

UINT32
HvCliTerminate(VOID)
{
    HANDLE device_handle = INVALID_HANDLE_VALUE;
    BOOL result = FALSE;
    DWORD bytes_returned = 0;
    HYPERCALL_HEADER header = {0};

    device_handle = CreateFileA(
        "\\\\.\\hv-link",
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (device_handle == INVALID_HANDLE_VALUE) {
        return HVSTATUS_DEVICE_OPEN_FAIL;
    }

    result = DeviceIoControl(
        device_handle,
        IOCTL_HYPERCALL_TERMINATE_VMX,
        &header,
        sizeof(header),
        &header,
        sizeof(header),
        &bytes_returned,
        NULL);

    CloseHandle(device_handle);

    return result ? HVSTATUS_SUCCESS : HVSTATUS_FAILURE;
}

UINT32
HvCliQueryStats(_Out_ PVCPU_STATS Stats)
{
    HANDLE device_handle = INVALID_HANDLE_VALUE;
    BOOL result = FALSE;
    DWORD bytes_returned = 0;
    HYPERCALL_QUERY_STATS buffer = {0};

    if (!Stats)
        return HVSTATUS_INVALID_PARAMETER;

    device_handle = CreateFileA(
        "\\\\.\\hv-link",
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (device_handle == INVALID_HANDLE_VALUE) {
        return HVSTATUS_DEVICE_OPEN_FAIL;
    }

    result = DeviceIoControl(
        device_handle,
        IOCTL_HYPERCALL_QUERY_STATS,
        &buffer,
        sizeof(buffer),
        &buffer,
        sizeof(buffer),
        &bytes_returned,
        NULL);

    CloseHandle(device_handle);

    if (!result || buffer.header.bytes_written < sizeof(VCPU_STATS)) {
        return HVSTATUS_FAILURE;
    }

    *Stats = buffer.stats;
    return HVSTATUS_SUCCESS;
}
