#include "driver.h"

#include "ept.h"

#include <intrin.h>
#include "vmx.h"
#include "common.h"

UNICODE_STRING device_name = RTL_CONSTANT_STRING(L"\\Device\\hv-dbg");
UNICODE_STRING device_link = RTL_CONSTANT_STRING(L"\\??\\hv-dbg-link");

STATIC
VOID
hvdbgTerminateVmx()
{
        for (ULONG index = 0; index < KeQueryActiveProcessorCount(0); index++)
        {
                KeSetSystemAffinityThread(1ull << index);

                __vmx_off();

                DEBUG_LOG("Vmx operation terminated on thread: %lx", index);

                if (vmm_state[index].vmcs_region_va)
                        MmFreeContiguousMemory(vmm_state[index].vmcs_region_va);

                if (vmm_state[index].vmxon_region_va)
                        MmFreeContiguousMemory(vmm_state[index].vmxon_region_va);
        }
}

NTSTATUS
DeviceClose(
        _In_ PDEVICE_OBJECT DeviceObject,
        _Inout_ PIRP Irp
)
{
        UNREFERENCED_PARAMETER(DeviceObject);
        hvdbgTerminateVmx();
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return Irp->IoStatus.Status;
}

NTSTATUS
DeviceCreate(
        _In_ PDEVICE_OBJECT DeviceObject,
        _Inout_ PIRP Irp
)
{
        UNREFERENCED_PARAMETER(DeviceObject);

        PIPI_CALL_CONTEXT context = ExAllocatePool2(POOL_FLAG_NON_PAGED, KeQueryActiveProcessorCount(0) * sizeof(IPI_CALL_CONTEXT), POOLTAG);

        if (!context)
                return STATUS_ABANDONED;

        PEPTP pept = InitializeEptp();

        for (int i = 0; i < KeQueryActiveProcessorCount(0); i++)
        {
                context[i].eptp = pept;
                context[i].guest_stack = NULL;
        }

        InitiateVmx(context);

        __try
        {
                BroadcastVmxInitiation(context);
        }
        __except (GetExceptionCode())
        {
        }
end:
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return Irp->IoStatus.Status;
}

NTSTATUS
DriverEntry(
        _In_ PDRIVER_OBJECT DriverObject,
        _In_ PUNICODE_STRING RegistryPath
)
{
        UNREFERENCED_PARAMETER(RegistryPath);

        NTSTATUS status = STATUS_SUCCESS;

        status = IoCreateDevice(
                DriverObject,
                0,
                &device_name,
                FILE_DEVICE_UNKNOWN,
                FILE_DEVICE_SECURE_OPEN,
                FALSE,
                &DriverObject->DeviceObject
        );

        if (!NT_SUCCESS(status))
                return STATUS_FAILED_DRIVER_ENTRY;

        status = IoCreateSymbolicLink(
                &device_link,
                &device_name
        );

        if (!NT_SUCCESS(status))
        {
                IoDeleteDevice(&DriverObject->DeviceObject);
                return STATUS_FAILED_DRIVER_ENTRY;
        }

        DriverObject->MajorFunction[IRP_MJ_CREATE] = DeviceCreate;
        DriverObject->MajorFunction[IRP_MJ_CLOSE] = DeviceClose;

        DEBUG_LOG("Driver entry complete");

        return status;
}