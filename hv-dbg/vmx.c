#include "vmx.h"

#include "common.h"
#include "ia32.h"
#include "pipeline.h"
#include "encode.h"
#include "arch.h"
#include "vmcs.h"

#include <intrin.h>
#include <Zydis/Zydis.h>

PVIRTUAL_MACHINE_STATE vmm_state;

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

STATIC
BOOLEAN
IsVmxSupported()
{
        CPUID cpuid = { 0 };

        __cpuid((INT*)&cpuid, 1);
        if ((cpuid.ecx & (1 << 5)) == 0)
                return FALSE;

        IA32_FEATURE_CONTROL_MSR Control = { 0 };
        Control.bit_address = __readmsr(MSR_IA32_FEATURE_CONTROL);

        if (Control.bits.Lock == 0)
        {
                Control.bits.Lock = TRUE;
                Control.bits.EnableVmxon = TRUE;
                __writemsr(MSR_IA32_FEATURE_CONTROL, Control.bit_address);
        }
        else if (Control.bits.EnableVmxon == FALSE)
        {
                DEBUG_LOG("VMX not enabled in the bios");
                return FALSE;
        }

        return TRUE;
}

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
        _In_ PVIRTUAL_MACHINE_STATE GuestState
)
{
        INT                status = 0;
        PVOID              virtual_allocation = NULL;
        UINT64             physical_allocation = NULL;
        PHYSICAL_ADDRESS   physical_max = { 0 };
        PHYSICAL_ADDRESS   physical_address = { 0 };
        IA32_VMX_BASIC_MSR ia32_basic_msr = { 0 };

        physical_max.QuadPart = MAXULONG64;

        virtual_allocation = MmAllocateContiguousMemory(PAGE_SIZE, physical_max);

        if (!virtual_allocation)
        {
                DEBUG_ERROR("Failed to allocate vmcs region");
                return FALSE;
        }

        RtlSecureZeroMemory(virtual_allocation, PAGE_SIZE);

        physical_allocation = MmGetPhysicalAddress(virtual_allocation).QuadPart;

        if (!physical_allocation)
        {
                DEBUG_LOG("Faield to get vmcs pa address");
                MmFreeContiguousMemory(virtual_allocation);
                return FALSE;
        }

        ia32_basic_msr.bit_address = __readmsr(MSR_IA32_VMX_BASIC);

        *(UINT64*)virtual_allocation = ia32_basic_msr.bits.RevisionIdentifier;

        GuestState->vmcs_region_pa = physical_allocation;

        return TRUE;
}

STATIC
BOOLEAN
hvdbgAllocateVmxonRegion(
        _In_ PVIRTUAL_MACHINE_STATE GuestState
)
{
        INT                status = 0;
        PVOID              virtual_allocation = NULL;
        UINT64             physical_allocation = NULL;
        PHYSICAL_ADDRESS   physical_max = { 0 };
        PHYSICAL_ADDRESS   physical_address = { 0 };
        IA32_VMX_BASIC_MSR ia32_basic_msr = { 0 };

        physical_max.QuadPart = MAXULONG64;

        virtual_allocation = MmAllocateContiguousMemory(PAGE_SIZE, physical_max);

        if (!virtual_allocation)
        {
                DEBUG_ERROR("MmAllocateContiguousMemory failed");
                return FALSE;
        }

        RtlSecureZeroMemory(virtual_allocation, PAGE_SIZE);

        physical_allocation = MmGetPhysicalAddress(virtual_allocation).QuadPart;

        if (!physical_allocation)
        {
                MmFreeContiguousMemory(virtual_allocation);
                return FALSE;
        }

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
                DEBUG_LOG("VmxOn failed with status: %i", status);
                MmFreeContiguousMemory(virtual_allocation);
                return FALSE;
        }

        GuestState->vmxon_region_pa = physical_allocation;

        return TRUE;
}

STATIC
BOOLEAN
AllocateVmmState()
{
        vmm_state = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(VIRTUAL_MACHINE_STATE) * KeQueryActiveProcessorCount(0), POOLTAG);
        return vmm_state != NULL ? TRUE : FALSE;
}

NTSTATUS
InitiateVmx(
        _In_ PIPI_CALL_CONTEXT Context
)
{
        if (!AllocateVmmState())
        {
                DEBUG_LOG("Failed to allocate vmm state");
                return STATUS_MEMORY_NOT_ALLOCATED;
        }

        for (ULONG core = 0; core < KeQueryActiveProcessorCount(0); core++)
        {
                /* for now this limits us to 64 cores, whatever lol */
                KeSetSystemAffinityThread(1ull << core);

                while (KeGetCurrentProcessorNumber() != core)
                        YieldProcessor();

                hvdbgEnableVmxOperationOnCore();

                ZyanStatus status = InitialiseDisassemblerState();

                if (!ZYAN_SUCCESS(status))
                {
                        DEBUG_ERROR("InitialiseDisassemblerState failed with status %x", status);
                        return STATUS_ABANDONED;
                }

                if (!hvdbgAllocateVmxonRegion(&vmm_state[core]))
                {
                        DEBUG_ERROR("AllocateVmxonRegion failed");
                        return STATUS_MEMORY_NOT_ALLOCATED;;
                }

                if (!hvdbgAllocateVmcsRegion(&vmm_state[core]))
                {
                        DEBUG_ERROR("AllocateVmcsRegion failed");
                        return STATUS_MEMORY_NOT_ALLOCATED;;
                }

                vmm_state[core].vmm_stack = ExAllocatePool2(POOL_FLAG_NON_PAGED, VMM_STACK_SIZE, POOLTAG);

                if (!vmm_state[core].vmm_stack)
                {
                        DEBUG_LOG("Error in allocating VMM Stack.");
                        return STATUS_MEMORY_NOT_ALLOCATED;;
                }

                vmm_state[core].msr_bitmap_va = MmAllocateNonCachedMemory(PAGE_SIZE);

                if (!vmm_state[core].msr_bitmap_va)
                {
                        DEBUG_LOG("Error in allocating MSRBitMap.");
                        return STATUS_MEMORY_NOT_ALLOCATED;;
                }

                RtlSecureZeroMemory(vmm_state[core].msr_bitmap_va, PAGE_SIZE);

                vmm_state[core].msr_bitmap_pa = MmGetPhysicalAddress(vmm_state[core].msr_bitmap_va).QuadPart;
        }
}

VOID
VirtualizeCore(
        _In_ PIPI_CALL_CONTEXT Context,
        _In_ PVOID StackPointer
)
{
        NTSTATUS status = SetupVmcs(&vmm_state[KeGetCurrentProcessorNumber()], StackPointer);

        if (!NT_SUCCESS(status))
        {
                DEBUG_ERROR("SetupVmcs failed with status %x", status);
                return;
        }

        __vmx_vmlaunch();

        /* only if vmlaunch fails will we end up here */
        DEBUG_ERROR("VMLAUNCH Error : 0x%llx", VmcsReadInstructionErrorCode());
}

STATIC
VOID
TerminateVmx(
        _In_ ULONG_PTR Argument
)
{
        UNREFERENCED_PARAMETER(Argument);

        __vmx_off();

        ULONG proc_num = KeGetCurrentProcessorNumber();

        if (MmGetPhysicalAddress(vmm_state[proc_num].vmxon_region_pa).QuadPart)
                MmFreeContiguousMemory(MmGetPhysicalAddress(vmm_state[proc_num].vmxon_region_pa).QuadPart);

        if (MmGetPhysicalAddress(vmm_state[proc_num].vmcs_region_pa).QuadPart)
                MmFreeContiguousMemory(MmGetPhysicalAddress(vmm_state[proc_num].vmcs_region_pa).QuadPart);

        if (vmm_state[KeGetCurrentNodeNumber()].msr_bitmap_va)
                MmFreeNonCachedMemory(vmm_state[proc_num].msr_bitmap_va, PAGE_SIZE);

        if (vmm_state[proc_num].vmm_stack)
                ExFreePoolWithTag(vmm_state[proc_num].vmm_stack, POOLTAG);

        DEBUG_LOG("Terminated VMX on processor index: %lx", proc_num);
}

BOOLEAN
BroadcastVmxInitiation(
        _In_ PIPI_CALL_CONTEXT Context
)
{
        if (!IsVmxSupported())
        {
                DEBUG_LOG("VMX operation is not supported on this machine");
                return FALSE;
        }

        KeIpiGenericCall(SaveStateAndVirtualizeCore, Context);

        return TRUE;
}

BOOLEAN
BroadcastVmxTermination()
{
        KeIpiGenericCall(TerminateVmx, NULL);
        return TRUE;
}
