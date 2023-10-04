#include "driver.h"

#include <intrin.h>

UNICODE_STRING device_name = RTL_CONSTANT_STRING(L"hv-dbg");
UNICODE_STRING device_link = RTL_CONSTANT_STRING(L"hv-dbg-link");

typedef struct _VMM_STATE
{
        UINT64 vmxon_region_va;
        UINT64 vmcs_region_va;
        UINT64 vmxon_region_pa;
        UINT64 vmcs_region_pa;

}VMM_STATE, *PVMM_STATE;

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

        *(UINT32*)virtual_allocation = ia32_basic_msr.bits.RevisionIdentifier;

        if (__vmx_vmptrld(&physical_allocation))
                return FALSE;

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

        *(UINT32*)virtual_allocation = ia32_basic_msr.bits.RevisionIdentifier;

        if (__vmx_on(&physical_allocation))
                return FALSE;

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

        if (!processor_count)
                return FALSE;

        vmm_state = ExAllocatePoolWithTag(
                POOL_FLAG_NON_PAGED, 
                processor_count * sizeof(VMM_STATE), 
                POOL_TAG_VMM);

        if (!vmm_state)
                return FALSE;

        for (ULONG index = 0; index < processor_count; index++)
        {
                KeSetSystemAffinityThread(1ull << index);
                hvdbgEnableVmxOperationOnCore();

                DEBUG_LOG("VMX Operation enable on core: %lx", index);

                hvdbgAllocateVmcsRegion(index);
                hvdbgAllocateVmxonRegion(index);
        }

        return TRUE;
}

NTSTATUS
DriverEntry(
        PDRIVER_OBJECT DriverObject,
        PUNICODE_STRING RegistryPath
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

        DEBUG_LOG("Driver entry complete");

        return status;
}