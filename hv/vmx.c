#include "vmx.h"

#include "common.h"
#include "ia32.h"
#include "encode.h"
#include "arch.h"
#include "vmcs.h"
#include "ept.h"

#include <intrin.h>

PDRIVER_STATE          driver_state = NULL;
PVIRTUAL_MACHINE_STATE vmm_state    = NULL;

/*
 * Assuming the thread calling this is binded to a particular core
 */
STATIC
NTSTATUS
EnableVmxOperationOnCore()
{
        CR4 cr4         = {0};
        cr4.bit_address = __readcr4();
        cr4.bits.vmxe   = TRUE;
        __writecr4(cr4.bit_address);

        return STATUS_SUCCESS;
}

STATIC
NTSTATUS
IsVmxSupported()
{
        CPUID cpuid = {0};

        __cpuid((INT*)&cpuid, 1);
        if ((cpuid.ecx & (1 << 5)) == 0)
                return STATUS_NOT_SUPPORTED;

        IA32_FEATURE_CONTROL_MSR Control = {0};
        Control.bit_address              = __readmsr(MSR_IA32_FEATURE_CONTROL);

        if (Control.bits.Lock == 0) {
                Control.bits.Lock        = TRUE;
                Control.bits.EnableVmxon = TRUE;
                __writemsr(MSR_IA32_FEATURE_CONTROL, Control.bit_address);
        }
        else if (Control.bits.EnableVmxon == FALSE) {
                DEBUG_LOG("VMX not enabled in the bios");
                return STATUS_NOT_SUPPORTED;
        }

        return STATUS_SUCCESS;
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
NTSTATUS
AllocateVmcsRegion(_In_ PVIRTUAL_MACHINE_STATE VmmState)
{
        INT                status              = 0;
        PVOID              virtual_allocation  = NULL;
        UINT64             physical_allocation = NULL;
        PHYSICAL_ADDRESS   physical_max        = {0};
        PHYSICAL_ADDRESS   physical_address    = {0};
        IA32_VMX_BASIC_MSR ia32_basic_msr      = {0};

        physical_max.QuadPart = MAXULONG64;

        virtual_allocation = MmAllocateContiguousMemory(PAGE_SIZE, physical_max);

        if (!virtual_allocation) {
                DEBUG_ERROR("Failed to allocate vmcs region");
                return STATUS_MEMORY_NOT_ALLOCATED;
        }

        RtlSecureZeroMemory(virtual_allocation, PAGE_SIZE);

        physical_allocation = MmGetPhysicalAddress(virtual_allocation).QuadPart;

        if (!physical_allocation) {
                DEBUG_LOG("Faield to get vmcs pa address");
                MmFreeContiguousMemory(virtual_allocation);
                return STATUS_MEMORY_NOT_ALLOCATED;
        }

        ia32_basic_msr.bit_address = __readmsr(MSR_IA32_VMX_BASIC);

        *(UINT64*)virtual_allocation = ia32_basic_msr.bits.RevisionIdentifier;

        VmmState->vmcs_region_pa = physical_allocation;

        return STATUS_SUCCESS;
}

STATIC
NTSTATUS
AllocateVmxonRegion(_In_ PVIRTUAL_MACHINE_STATE VmmState)
{
        INT                status              = 0;
        PVOID              virtual_allocation  = NULL;
        UINT64             physical_allocation = NULL;
        PHYSICAL_ADDRESS   physical_max        = {0};
        PHYSICAL_ADDRESS   physical_address    = {0};
        IA32_VMX_BASIC_MSR ia32_basic_msr      = {0};

        physical_max.QuadPart = MAXULONG64;

        virtual_allocation = MmAllocateContiguousMemory(PAGE_SIZE, physical_max);

        if (!virtual_allocation) {
                DEBUG_ERROR("MmAllocateContiguousMemory failed");
                return STATUS_MEMORY_NOT_ALLOCATED;
        }

        RtlSecureZeroMemory(virtual_allocation, PAGE_SIZE);

        physical_allocation = MmGetPhysicalAddress(virtual_allocation).QuadPart;

        if (!physical_allocation) {
                MmFreeContiguousMemory(virtual_allocation);
                return STATUS_MEMORY_NOT_ALLOCATED;
        }

        ia32_basic_msr.bit_address = __readmsr(MSR_IA32_VMX_BASIC);

        *(UINT64*)virtual_allocation = ia32_basic_msr.bits.RevisionIdentifier;

        status = __vmx_on(&physical_allocation);

        /*
         * 0 : The operation succeeded
         * 1 : The operation failed with extended status available in the
         * VM-instruction error field of the current VMCS. 2 : The operation
         * failed without status available.
         */
        if (status) {
                DEBUG_LOG("VmxOn failed with status: %i", status);
                MmFreeContiguousMemory(virtual_allocation);
                return STATUS_FAIL_CHECK;
        }

        VmmState->vmxon_region_pa = physical_allocation;

        return STATUS_SUCCESS;
}

NTSTATUS
AllocateDriverState()
{
        driver_state = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(DRIVER_STATE), POOLTAG);

        if (!driver_state)
                return STATUS_MEMORY_NOT_ALLOCATED;

        return STATUS_SUCCESS;
}

STATIC
NTSTATUS
InitiateVmmState(_In_ PVIRTUAL_MACHINE_STATE VmmState)
{
        VmmState->cache.cpuid.active  = FALSE;
        VmmState->exit_state.exit_vmx = FALSE;

        return STATUS_SUCCESS;
}

STATIC
NTSTATUS
AllocateVmmStack(_In_ PVIRTUAL_MACHINE_STATE VmmState)
{
        VmmState->vmm_stack_va = ExAllocatePool2(POOL_FLAG_NON_PAGED, VMM_STACK_SIZE, POOLTAG);

        if (!VmmState->vmm_stack_va) {
                DEBUG_LOG("Error in allocating VMM Stack.");
                return STATUS_MEMORY_NOT_ALLOCATED;
        }

        return STATUS_SUCCESS;
}

STATIC
NTSTATUS
AllocateMsrBitmap(_In_ PVIRTUAL_MACHINE_STATE VmmState)
{
        VmmState->msr_bitmap_va = MmAllocateNonCachedMemory(PAGE_SIZE);

        if (!VmmState->msr_bitmap_va) {
                DEBUG_LOG("Error in allocating MSRBitMap.");
                return STATUS_MEMORY_NOT_ALLOCATED;
        }

        RtlSecureZeroMemory(VmmState->msr_bitmap_va, PAGE_SIZE);

        VmmState->msr_bitmap_pa = MmGetPhysicalAddress(VmmState->msr_bitmap_va).QuadPart;

        return STATUS_SUCCESS;
}

STATIC
NTSTATUS
AllocateVmmStateStructure()
{
        vmm_state = ExAllocatePool2(POOL_FLAG_NON_PAGED,
                                    sizeof(VIRTUAL_MACHINE_STATE) * KeQueryActiveProcessorCount(0),
                                    POOLTAG);
        if (!vmm_state) {
                DEBUG_LOG("Failed to allocate vmm state");
                return STATUS_MEMORY_NOT_ALLOCATED;
        }

        return STATUS_SUCCESS;
}

NTSTATUS
InitiateVmx(_In_ PIPI_CALL_CONTEXT Context)
{
        NTSTATUS status = STATUS_ABANDONED;

        status = AllocateVmmStateStructure();

        if (!NT_SUCCESS(status)) {
                DEBUG_ERROR("AllocateVmmStateStructure failed with status %x", status);
                return status;
        }

        for (UINT64 core = 0; core < KeQueryActiveProcessorCount(0); core++) {
                /* for now this limits us to 64 cores, whatever lol */
                KeSetSystemAffinityThread(1ull << core);

                while (KeGetCurrentProcessorNumber() != core)
                        YieldProcessor();

                status = EnableVmxOperationOnCore();

                if (!NT_SUCCESS(status)) {
                        DEBUG_ERROR("EnableVmxOperationOnCore failed with status %x", status);
                        return status;
                }

                status = AllocateVmxonRegion(&vmm_state[core]);

                if (!NT_SUCCESS(status)) {
                        DEBUG_ERROR("AllocateVmxonRegion failed with status %x", status);
                        return status;
                }

                status = AllocateVmcsRegion(&vmm_state[core]);

                if (!NT_SUCCESS(status)) {
                        DEBUG_ERROR("AllocateVmcsRegion failed with status %x", status);
                        return status;
                }

                status = AllocateVmmStack(&vmm_state[core]);

                if (!NT_SUCCESS(status)) {
                        DEBUG_ERROR("AllocateVmmStack failed with status %x", status);
                        return status;
                }

                status = AllocateMsrBitmap(&vmm_state[core]);

                if (!NT_SUCCESS(status)) {
                        DEBUG_ERROR("AllocateMsrBitmap failed with status %x", status);
                        return status;
                }

                status = InitiateVmmState(&vmm_state[core]);

                if (!NT_SUCCESS(status)) {
                        DEBUG_ERROR("InitiateVmmState failed with status %x", status);
                        return status;
                }
        }

        KeSetSystemAffinityThread((KAFFINITY)0ull);
        return STATUS_SUCCESS;
}

VOID
VirtualizeCore(_In_ PIPI_CALL_CONTEXT Context, _In_ PVOID StackPointer)
{
        NTSTATUS status = SetupVmcs(&vmm_state[KeGetCurrentProcessorNumber()], StackPointer);

        if (!NT_SUCCESS(status)) {
                DEBUG_ERROR("SetupVmcs failed with status %x", status);
                return;
        }

        __vmx_vmlaunch();

        /* only if vmlaunch fails will we end up here */
        DEBUG_ERROR("vmlaunch failed with status %lx", VmxVmRead(VMCS_VM_INSTRUCTION_ERROR));
}

NTSTATUS
BroadcastVmxInitiation(_In_ PIPI_CALL_CONTEXT Context)
{
        NTSTATUS status = IsVmxSupported();

        if (!NT_SUCCESS(status)) {
                DEBUG_LOG("VMX operation is not supported on this machine");
                return status;
        }

        KeIpiGenericCall(SaveStateAndVirtualizeCore, Context);
        return status;
}

NTSTATUS
VmxVmCall(VMCALL_ID Id, UINT64 OptionalParam1, UINT64 OptionalParam2, UINT64 OptionalParam3)
{
        NTSTATUS status = __vmx_vmcall(Id, OptionalParam1, OptionalParam2, OptionalParam3);

        if (!NT_SUCCESS(status))
                DEBUG_ERROR("VmCall failed wtih status %x", status);

        return status;
}

VOID
FreeCoreVmxState(_In_ UINT32 Core)
{
        PVIRTUAL_MACHINE_STATE vcpu = &vmm_state[Core];

        if (vcpu->vmxon_region_va)
                MmFreeContiguousMemory(vcpu->vmxon_region_va);
        if (vcpu->vmcs_region_va)
                MmFreeContiguousMemory(vcpu->vmcs_region_va);
        if (vcpu->msr_bitmap_va)
                MmFreeNonCachedMemory(vcpu->msr_bitmap_va, PAGE_SIZE);
        if (vcpu->vmm_stack_va)
                ExFreePoolWithTag(vcpu->vmm_stack_va, POOLTAG);
}

VOID
FreeGlobalVmmState()
{
        if (vmm_state) {
                ExFreePoolWithTag(vmm_state, POOLTAG);
                vmm_state = NULL;
        }
}

NTSTATUS
BroadcastVmxTermination()
{
        for (UINT64 core = 0; core < KeQueryActiveProcessorCount(0); core++) {
                KeSetSystemAffinityThread(1ull << core);

                while (core != KeGetCurrentProcessorIndex())
                        YieldProcessor();

                if (!NT_SUCCESS(VmxVmCall(TERMINATE_VMX, 0, 0, 0))) {
                        return STATUS_UNSUCCESSFUL;
                }

                /*
                 * At this point, we have exited VMX operation and we can safely free our per core
                 * allocations.
                 */
                FreeCoreVmxState(core);
        }

        /*
         * Now that each per core stuctures have been freed, we are safe to revert the affinity of
         * the current thread and free the global vmm state array.
         */
        KeSetSystemAffinityThread((KAFFINITY)0ull);
        FreeGlobalVmmState();
        return STATUS_SUCCESS;
}

NTSTATUS
SetupVmxOperation()
{
        NTSTATUS          status  = STATUS_UNSUCCESSFUL;
        PIPI_CALL_CONTEXT context = NULL;
        EPT_POINTER*      pept    = NULL;

        context = ExAllocatePool2(POOL_FLAG_NON_PAGED,
                                  KeQueryActiveProcessorCount(0) * sizeof(IPI_CALL_CONTEXT),
                                  POOLTAG);

        if (!context)
                goto end;

        status = InitializeEptp(&pept);

        if (!NT_SUCCESS(status)) {
                DEBUG_ERROR("Failed to initialise EPT");
                goto end;
        }

        for (INT core = 0; core < KeQueryActiveProcessorCount(0); core++) {
                context[core].eptp        = pept;
                context[core].guest_stack = NULL;
        }

        status = InitiateVmx(context);

        if (!NT_SUCCESS(status)) {
                DEBUG_ERROR("InitiateVmx failed with status %x", status);
                goto end;
        }

        status = BroadcastVmxInitiation(context);

        if (!NT_SUCCESS(status)) {
                DEBUG_ERROR("BroadcastVmxInitiation failed with status %x", status);
                goto end;
        }

end:
        if (context)
                ExFreePoolWithTag(context, POOLTAG);

        return status;
}

VOID
TerminatePowerCallback()
{
        if (driver_state->power_callback)
                ExUnregisterCallback(driver_state->power_callback);

        if (driver_state->power_callback_object)
                ObDereferenceObject(driver_state->power_callback_object);
}

/*
 * Argument1 consists of a set of constants cast to a void*. In our case we are only interested in
 * the PO_CB_SYSTEM_STATE_LOCK argument. This argument denotes a change in the system power policy
 * has changed.
 *
 * When Argument1 is equal to PO_CB_SYSTEM_STATE_LOCK, Argument2 is FALSE if the computer is about
 * to exit system power state s0, and is TRUE if the computer has just reentered s0.
 */
STATIC
VOID
PowerCallbackRoutine(_In_ PVOID CallbackContext, PVOID Argument1, PVOID Argument2)
{
        UNREFERENCED_PARAMETER(CallbackContext);

        NTSTATUS status = STATUS_UNSUCCESSFUL;
        HANDLE   handle = NULL;

        if (Argument1 != (PVOID)PO_CB_SYSTEM_STATE_LOCK)
                return;

        if (Argument2) {
                DEBUG_LOG("Resuming VMX operation after sleep..");

                status = SetupVmxOperation();

                if (!NT_SUCCESS(status))
                        DEBUG_ERROR("SetupVmxOperation failed with status %x", status);
        }
        else {
                DEBUG_LOG("Exiting VMX operation for sleep...");

                status = BroadcastVmxTermination();

                if (!NT_SUCCESS(status))
                        DEBUG_ERROR("BroadcastVmxTermination failed with status %x", status);
        }
}

NTSTATUS
InitialisePowerCallback()
{
        NTSTATUS          status = STATUS_ABANDONED;
        UNICODE_STRING    name   = RTL_CONSTANT_STRING(L"\\Callback\\PowerState");
        OBJECT_ATTRIBUTES object_attributes =
            RTL_CONSTANT_OBJECT_ATTRIBUTES(&name, OBJ_CASE_INSENSITIVE);

        status =
            ExCreateCallback(&driver_state->power_callback_object, &object_attributes, FALSE, TRUE);

        if (!NT_SUCCESS(status)) {
                DEBUG_ERROR("ExCreateCallback failed with status %x", status);
                return status;
        }

        driver_state->power_callback =
            ExRegisterCallback(driver_state->power_callback_object, PowerCallbackRoutine, NULL);

        if (!driver_state->power_callback) {
                DEBUG_ERROR("ExRegisterCallback failed");
                ObDereferenceObject(driver_state->power_callback_object);
                driver_state->power_callback_object = NULL;
                return STATUS_UNSUCCESSFUL;
        }

        return status;
}