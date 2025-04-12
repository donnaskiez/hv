#include "driver.h"

#include <intrin.h>
#include "vmx.h"
#include "common.h"
#include "hypercall.h"

#include <intrin.h>
#include "arch.h"

UNICODE_STRING device_name = RTL_CONSTANT_STRING(L"\\Device\\hv");
UNICODE_STRING device_link = RTL_CONSTANT_STRING(L"\\??\\hv-link");

NTSTATUS
HvDrvClose(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Irp->IoStatus.Status;
}

NTSTATUS
HvDrvCreate(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Irp->IoStatus.Status;
}

NTSTATUS
HvDrvDeviceControl(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    PIO_STACK_LOCATION io = IoGetCurrentIrpStackLocation(Irp);

    /* Pass the IOCTL to our hypercall handler */
    status = HvHypercallDispatchFromGuest(Irp, io);

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

VOID
DriverUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    DEBUG_LOG("Unloading driver...");
    HvVmxBroadcastTermination();
    HvVmxPowerCbUnregister();
    HvVmxFreeDriverState();
    IoDeleteSymbolicLink(&device_link);
    IoDeleteDevice(DriverObject->DeviceObject);
    DEBUG_LOG("Driver unloaded.");
}

NTSTATUS
DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS status = STATUS_SUCCESS;

    DriverObject->MajorFunction[IRP_MJ_CREATE] = HvDrvCreate;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = HvDrvClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = HvDrvDeviceControl;
    DriverObject->DriverUnload = DriverUnload;

    status = IoCreateDevice(
        DriverObject,
        0,
        &device_name,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &DriverObject->DeviceObject);
    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR("IoCreateDevice failed with status %x", status);
        return status;
    }

    status = IoCreateSymbolicLink(&device_link, &device_name);
    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR("IoCreateSymbolicLink failed with status %x", status);
        IoDeleteDevice(DriverObject->DeviceObject);
        return status;
    }

    status = HvVmxAllocateDriverState();
    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR("AllocateDriverState failed with status %x", status);
        IoDeleteSymbolicLink(&device_link);
        IoDeleteDevice(DriverObject->DeviceObject);
        return status;
    }

    status = HvVmxPowerCbInit();
    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR("InitialisePowerCallback failed with status %x", status);
        HvVmxFreeDriverState();
        IoDeleteSymbolicLink(&device_link);
        IoDeleteDevice(DriverObject->DeviceObject);
        return status;
    }

    status = HvVmxInitialiseOperation();
    if (!NT_SUCCESS(status)) {
        DEBUG_ERROR("SetupVmxOperation failed with status %x", status);
        HvVmxPowerCbUnregister();
        HvVmxFreeDriverState();
        IoDeleteSymbolicLink(&device_link);
        IoDeleteDevice(DriverObject->DeviceObject);
        return status;
    }

    DEBUG_LOG("Driver entry complete");
    return status;
}