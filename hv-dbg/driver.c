#include "driver.h"

#include <intrin.h>

UNICODE_STRING device_name = RTL_CONSTANT_STRING(L"\\Device\\hv-dbg");
UNICODE_STRING device_link = RTL_CONSTANT_STRING(L"\\??\\hv-dbg-link");

PVMM_STATE vmm_state = NULL;

/*
* VMCS region comprises up to 4096 bytes, with the following format:
* 
* offset 0: VMCS revision identifier
* offset 4: VMX abort indicator
* offset 8: VMCS data
* 
* Source: 3c 24.2
*/
STATIC
BOOLEAN
hvdbgAllocateVmcsRegion(
        _In_ ULONG CoreNumber
)
{
        INT status = 0;
        PVOID virtual_allocation = NULL;
        PVOID physical_allocation = NULL;
        PHYSICAL_ADDRESS physical_max = { 0 };
        PHYSICAL_ADDRESS physical_address = { 0 };
        IA32_VMX_BASIC_MSR ia32_basic_msr = { 0 };

        if (!CoreNumber)
                return FALSE;

        physical_max.QuadPart = MAXULONG64;

        virtual_allocation = MmAllocateContiguousMemory(
                ALIGNMENT_PAGE_SIZE,
                physical_max
        );

        if (!virtual_allocation)
                return FALSE;

        RtlSecureZeroMemory(virtual_allocation, ALIGNMENT_PAGE_SIZE);

        physical_address = MmGetPhysicalAddress(virtual_allocation);

        if (!physical_address.QuadPart)
        {
                MmFreeContiguousMemory(virtual_allocation);
                return FALSE;
        }

        physical_allocation = (PVOID)physical_address.QuadPart;

        ia32_basic_msr.bit_address = __readmsr(MSR_IA32_VMX_BASIC);

        *(UINT64*)virtual_allocation = ia32_basic_msr.bits.RevisionIdentifier;

        status = __vmx_vmptrld(&physical_allocation);

        if (status)
        {
                DEBUG_LOG("VmxVmPtrLd failed with status: %i", status);
                MmFreeContiguousMemory(virtual_allocation);
                return FALSE;
        }

        vmm_state[CoreNumber].vmxon_region_pa = (UINT64)physical_allocation;
        vmm_state[CoreNumber].vmxon_region_va = (UINT64)virtual_allocation;

        return TRUE;
}

STATIC
BOOLEAN
hvdbgAllocateVmxonRegion(
        _In_ CoreNumber
)
{
        INT status = 0;
        PVOID virtual_allocation = NULL;
        PVOID physical_allocation = NULL;
        PHYSICAL_ADDRESS physical_max = { 0 };
        PHYSICAL_ADDRESS physical_address = { 0 };
        IA32_VMX_BASIC_MSR ia32_basic_msr = { 0 };

        if (!CoreNumber)
                return FALSE;

        physical_max.QuadPart = MAXULONG64;

        virtual_allocation = MmAllocateContiguousMemory(
                ALIGNMENT_PAGE_SIZE,
                physical_max
        );

        if (!virtual_allocation)
                return FALSE;

        RtlSecureZeroMemory(virtual_allocation, ALIGNMENT_PAGE_SIZE);

        physical_address = MmGetPhysicalAddress(virtual_allocation);

        if (!physical_address.QuadPart)
        {
                MmFreeContiguousMemory(virtual_allocation);
                return FALSE;
        }

        physical_allocation = (PVOID)physical_address.QuadPart;

        ia32_basic_msr.bit_address = __readmsr(MSR_IA32_VMX_BASIC);

        *(UINT64*)virtual_allocation = ia32_basic_msr.bits.RevisionIdentifier;

        status = __vmx_on(&physical_allocation);

        /*
        * 0 : The operation succeeded
        * 1 : The operation failed with extended status available in the VM-instruction error field of the current VMCS.
        * 2 : The operation failed without status available.
        */
        if (status)
        {
                DEBUG_ERROR("VmxOn failed with status: %i", status);
                MmFreeContiguousMemory(virtual_allocation);
                return FALSE;
        }

        vmm_state[CoreNumber].vmcs_region_pa = (UINT64)physical_allocation;
        vmm_state[CoreNumber].vmcs_region_va = (UINT64)virtual_allocation;

        return TRUE;
}

/*
* Here we check for vmx support by checking the CPUID.1:ECX.VMX[bit 5]
* https://en.wikipedia.org/wiki/CPUID#EAX=1:_Processor_Info_and_Feature_Bits
* Source: 3c 23.6
* 
* We then enable the use of VMXON inside and outside of SMX. 
* Source: 3c 23.7
*/
STATIC
BOOLEAN
hvdbgIsVmxSupported()
{
        CPUID cpuid = { 0 };
        IA32_FEATURE_CONTROL_MSR control_msr = { 0 };

        __cpuid((INT*)&cpuid, 1);

        if ((cpuid.ecx & (1 << 5)) == FALSE)
                return FALSE;

        control_msr.bit_address = __readmsr(MSR_IA32_FEATURE_CONTROL);

        if (control_msr.bits.Lock == FALSE)
        {
                control_msr.bits.Lock = TRUE;
                control_msr.bits.EnableVmxon = TRUE;

                __writemsr(MSR_IA32_FEATURE_CONTROL, control_msr.bit_address);
        }
        else if (control_msr.bits.EnableVmxon == FALSE)
        {
                DEBUG_LOG("VMX locked off in BIOS");
                return FALSE;
        }

        return TRUE;
}

/*
* Assuming the thread calling this is binded to a particular core
*/
STATIC
VOID
hvdbgEnableVmxOperationOnCore()
{
        CR4 cr4 = { 0 };
        cr4.bit_address = __readcr4();
        cr4.bits.vmxe = TRUE;
        __writecr4(cr4.bit_address);
}

/*
* Initialise VMX operation on each logical core
*/
STATIC
BOOLEAN
hvdbgInitiateVmxOperation()
{
        ULONG processor_count = 0;

        if (!hvdbgIsVmxSupported())
                return FALSE;

        processor_count = KeQueryActiveProcessorCount(0);

        DEBUG_LOG("proc count: %lx", processor_count);

        if (!processor_count)
                return FALSE;

        vmm_state = ExAllocatePoolWithTag(POOL_FLAG_NON_PAGED, processor_count * sizeof(VMM_STATE), POOL_TAG_VMM);

        if (!vmm_state)
                return FALSE;

        for (ULONG index = 0; index < processor_count; index++)
        {
                KeSetSystemAffinityThread(1ull << index);
                hvdbgEnableVmxOperationOnCore();
                hvdbgAllocateVmcsRegion(index);
                hvdbgAllocateVmxonRegion(index);

                DEBUG_LOG("VMX Operation enable on core: %lx", index);
        }

        return TRUE;
}

STATIC
NTSTATUS
hvdgInitiateGuestStateArea()
{
        NTSTATUS status = STATUS_SUCCESS;


}

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
        hvdbgInitiateVmxOperation();
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