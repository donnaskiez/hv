#include "vmx.h"
#include "ept.h"
#include "common.h"
#include "ia32.h"
#include "pipeline.h"

#include <intrin.h>
#include <Zydis/Zydis.h>

PVIRTUAL_MACHINE_STATE vmm_state;
ULONG proc_count;

VMCS_GUEST_STATE_FIELDS   guest_state_fields = { 0 };
VMCS_HOST_STATE_FIELDS    host_state_fields = { 0 };
VMCS_CONTROL_STATE_FIELDS control_state_fields = { 0 };

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

        virtual_allocation = MmAllocateContiguousMemory(
                ALIGNMENT_PAGE_SIZE * 2,
                physical_max);

        if (!virtual_allocation)
                return FALSE;

        RtlSecureZeroMemory(virtual_allocation, ALIGNMENT_PAGE_SIZE * 2);

        physical_allocation = MmGetPhysicalAddress(virtual_allocation).QuadPart;

        if (!physical_allocation)
        {
                MmFreeContiguousMemory(virtual_allocation);
                return FALSE;
        }

        ia32_basic_msr.bit_address = __readmsr(MSR_IA32_VMX_BASIC);

        *(UINT64*)virtual_allocation = ia32_basic_msr.bits.RevisionIdentifier;

        vmm_state->vmcs_region_pa = physical_allocation;

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

        virtual_allocation = MmAllocateContiguousMemory(
                ALIGNMENT_PAGE_SIZE,
                physical_max);

        if (!virtual_allocation)
                return FALSE;

        RtlSecureZeroMemory(virtual_allocation, ALIGNMENT_PAGE_SIZE);

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

        vmm_state->vmxon_region_pa = physical_allocation;

        return TRUE;
}

STATIC
BOOLEAN
AllocateVmmState()
{
        vmm_state = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(VIRTUAL_MACHINE_STATE) * KeQueryActiveProcessorCount(0), POOLTAG);
        return vmm_state != NULL ? TRUE : FALSE;
}

VOID
InitiateVmx(
        _In_ PIPI_CALL_CONTEXT Context
)
{
        if (!AllocateVmmState())
        {
                DEBUG_LOG("Failed to allocate vmm state");
                return;
        }

        for (INT core = 0; core < KeQueryActiveProcessorCount(0); core++)
        {
                /* for now this limits us to 64 cores, whatever lol */
                KeSetSystemAffinityThread(1ull << core);

                DEBUG_LOG("Executing InitiateVmx on processor index: %lx", core);

                hvdbgEnableVmxOperationOnCore();

                //ZyanStatus status = InitialiseDisassemblerState();
                
                //if (!ZYAN_SUCCESS(status))
                //{
                //        DEBUG_ERROR("InitialiseDisassemblerState failed with status %x", status);
                //        return;
                //}

                if (!hvdbgAllocateVmxonRegion(&vmm_state[core]))
                {
                        DEBUG_ERROR("AllocateVmxonRegion failed");
                        return;
                }

                if (!hvdbgAllocateVmcsRegion(&vmm_state[core]))
                {
                        DEBUG_ERROR("AllocateVmcsRegion failed");
                        return;
                }

                vmm_state[core].vmm_stack = ExAllocatePool2(POOL_FLAG_NON_PAGED, VMM_STACK_SIZE, POOLTAG);

                if (!vmm_state[core].vmm_stack)
                {
                        DEBUG_LOG("Error in allocating VMM Stack.");
                        return;
                }

                vmm_state[core].msr_bitmap_va = MmAllocateNonCachedMemory(PAGE_SIZE); // should be aligned

                if (!vmm_state[core].msr_bitmap_va)
                {
                        DEBUG_LOG("Error in allocating MSRBitMap.");
                        return;
                }
                RtlSecureZeroMemory(vmm_state[core].msr_bitmap_va, PAGE_SIZE);

                vmm_state[core].msr_bitmap_pa = MmGetPhysicalAddress(vmm_state[core].msr_bitmap_va).QuadPart;

                DEBUG_LOG("VMX initiated on core: %lx", KeGetCurrentProcessorNumber());
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

        /*
        * If vmlaunch succeeds, we will never get here.
        */
        ULONG64 error_code = 0;

        __vmx_vmread(VM_INSTRUCTION_ERROR, &error_code);
        __vmx_off();

        DEBUG_ERROR("VMLAUNCH Error : 0x%llx", error_code);

success:

        __vmx_off();
        return TRUE;
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

        DEBUG_LOG("Eptp broadcast: %llx", (UINT64)Context->eptp);

        KeIpiGenericCall(SaveStateAndVirtualizeCore, Context);
        return TRUE;
}

BOOLEAN
BroadcastVmxTermination()
{
        KeIpiGenericCall(TerminateVmx, NULL);
}

STATIC
BOOLEAN
GetSegmentDescriptor(
        PSEGMENT_SELECTOR SegmentSelector,
        USHORT            Selector,
        PUCHAR            GdtBase
)
{
        ULONG64 temp;
        PSEGMENT_DESCRIPTOR segment_descriptor;

        if (!SegmentSelector)
                return FALSE;

        if (Selector & 0x4)
                return FALSE;

        segment_descriptor = (PSEGMENT_DESCRIPTOR)((PUCHAR)GdtBase + (Selector & ~0x7));

        SegmentSelector->SEL = Selector;
        SegmentSelector->BASE = segment_descriptor->BASE0 | segment_descriptor->BASE1 << 16 | segment_descriptor->BASE2 << 24;
        SegmentSelector->LIMIT = segment_descriptor->LIMIT0 | (segment_descriptor->LIMIT1ATTR1 & 0xf) << 16;
        SegmentSelector->ATTRIBUTES.UCHARs = segment_descriptor->ATTR0 | (segment_descriptor->LIMIT1ATTR1 & 0xf0) << 4;

        if (!(segment_descriptor->ATTR0 & 0x10))
        {
                // this is a TSS or callgate etc, save the base high part
                temp = (*(PULONG64)((PUCHAR)segment_descriptor + 8));
                SegmentSelector->BASE = (SegmentSelector->BASE & 0xffffffff) | (temp << 32);
        }

        if (SegmentSelector->ATTRIBUTES.Fields.G)
        {
                // 4096-bit granularity is enabled for this segment, scale the limit
                SegmentSelector->LIMIT = (SegmentSelector->LIMIT << 12) + 0xfff;
        }

        return TRUE;
}

ULONG
AdjustMsrControl(
        _In_ ULONG Control,
        _In_ ULONG  Msr
)
{
        MSR MsrValue = { 0 };

        MsrValue.Content = __readmsr(Msr);
        Control &= MsrValue.High; /* bit == 0 in high word ==> must be zero */
        Control |= MsrValue.Low;  /* bit == 1 in low word  ==> must be one  */
        return Control;
}

VOID
__vmx_fill_selector_data(
        _In_ PVOID  GdtBase,
        _In_ ULONG  Segreg,
        _In_ USHORT Selector)
{
        SEGMENT_SELECTOR segment_selector = { 0 };
        ULONG            access_rights;

        GetSegmentDescriptor(&segment_selector, Selector, GdtBase);
        access_rights = ((PUCHAR)&segment_selector.ATTRIBUTES)[0] + (((PUCHAR)&segment_selector.ATTRIBUTES)[1] << 12);

        if (!Selector)
                access_rights |= 0x10000;

        __vmx_vmwrite(guest_state_fields.word_state.es_selector + Segreg * 2, Selector);
        __vmx_vmwrite(guest_state_fields.dword_state.es_limit + Segreg * 2, segment_selector.LIMIT);
        __vmx_vmwrite(GUEST_ES_AR_BYTES + Segreg * 2, access_rights);
        __vmx_vmwrite(GUEST_ES_BASE + Segreg * 2, segment_selector.BASE);
}

STATIC
UINT32
EncodeField(
        _In_ VMCS_ACCESS_TYPE AccessType,
        _In_ VMCS_TYPE        Type,
        _In_ VMCS_WIDTH       Width,
        _In_ UINT8            Index)
{
        VMCS_ENCODING encoding =
        {
            .bits.access_type = AccessType,
            .bits.type = Type,
            .bits.width = Width,
            .bits.index = Index
        };

        return encoding.address;
}

STATIC
VOID
EncodeVmcsGuestStateFields(
        _Out_ PVMCS_GUEST_STATE_FIELDS Fields)
{
        Fields->natural_state.cr0 = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_NATURAL, 0);
        Fields->natural_state.cr3 = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_NATURAL, 1);
        Fields->natural_state.cr4 = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_NATURAL, 2);
        Fields->natural_state.es_base = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_NATURAL, 3);
        Fields->natural_state.cs_base = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_NATURAL, 4);
        Fields->natural_state.ss_base = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_NATURAL, 5);
        Fields->natural_state.ds_base = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_NATURAL, 6);
        Fields->natural_state.fs_base = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_NATURAL, 7);
        Fields->natural_state.gs_base = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_NATURAL, 8);
        Fields->natural_state.ldtr_base = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_NATURAL, 9);
        Fields->natural_state.tr_base = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_NATURAL, 10);
        Fields->natural_state.gdtr_base = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_NATURAL, 11);
        Fields->natural_state.idtr_base = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_NATURAL, 12);
        Fields->natural_state.dr7 = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_NATURAL, 13);
        Fields->natural_state.rsp = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_NATURAL, 14);
        Fields->natural_state.rip = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_NATURAL, 15);
        Fields->natural_state.rflags = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_NATURAL, 16);
        //pending_debug_exceptions
        Fields->natural_state.sysenter_esp = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_NATURAL, 18);
        Fields->natural_state.sysenter_eip = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_NATURAL, 19);

        /* 64 bit state fields */

        Fields->qword_state.vmcs_link_pointer = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_64, 0);
        Fields->qword_state.debug_control = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_64, 1);
        Fields->qword_state.pat = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_64, 2);
        Fields->qword_state.efer = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_64, 3);
        Fields->qword_state.perf_global_control = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_64, 4);
        //Fields->qword_state.bndcfgs             = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_64, 5);

        /* 32 bit state fields */

        Fields->dword_state.es_limit = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_32, 0);
        Fields->dword_state.cs_limit = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_32, 1);
        Fields->dword_state.ss_limit = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_32, 2);
        Fields->dword_state.ds_limit = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_32, 3);
        Fields->dword_state.fs_limit = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_32, 4);
        Fields->dword_state.gs_limit = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_32, 5);
        Fields->dword_state.ldtr_limit = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_32, 6);
        Fields->dword_state.tr_limit = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_32, 7);
        Fields->dword_state.gdtr_limit = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_32, 8);
        Fields->dword_state.idtr_limit = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_32, 9);
        Fields->dword_state.es_access_rights = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_32, 10);
        Fields->dword_state.cs_access_rights = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_32, 11);
        Fields->dword_state.ss_access_rights = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_32, 12);
        Fields->dword_state.ds_access_rights = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_32, 13);
        Fields->dword_state.fs_access_rights = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_32, 14);
        Fields->dword_state.gs_access_rights = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_32, 15);
        Fields->dword_state.ldtr_access_rights = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_32, 16);
        Fields->dword_state.tr_access_rights = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_32, 17);

        Fields->dword_state.smbase = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_32, 20);
        Fields->dword_state.sysenter_cs = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_32, 21);

        /* 16 bit fields */

        Fields->word_state.es_selector = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_16, 0);
        Fields->word_state.cs_selector = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_16, 1);
        Fields->word_state.ss_selector = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_16, 2);
        Fields->word_state.ds_selector = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_16, 3);
        Fields->word_state.fs_selector = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_16, 4);
        Fields->word_state.gs_selector = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_16, 5);
        Fields->word_state.ldtr_selector = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_16, 6);
        Fields->word_state.tr_selector = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_16, 7);
}

STATIC
VOID
EncodeVmcsHostStateFields(
        _Out_ PVMCS_HOST_STATE_FIELDS Fields)
{
        /* natural */

        Fields->natural_state.cr0 = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_HOST_STATE, VMCS_WIDTH_NATURAL, 0);
        Fields->natural_state.cr3 = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_HOST_STATE, VMCS_WIDTH_NATURAL, 1);
        Fields->natural_state.cr4 = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_HOST_STATE, VMCS_WIDTH_NATURAL, 2);
        Fields->natural_state.fs_base = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_HOST_STATE, VMCS_WIDTH_NATURAL, 3);
        Fields->natural_state.gs_base = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_HOST_STATE, VMCS_WIDTH_NATURAL, 4);
        Fields->natural_state.tr_base = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_HOST_STATE, VMCS_WIDTH_NATURAL, 5);
        Fields->natural_state.gdtr_base = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_HOST_STATE, VMCS_WIDTH_NATURAL, 6);
        Fields->natural_state.idtr_base = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_HOST_STATE, VMCS_WIDTH_NATURAL, 7);
        Fields->natural_state.ia32_sysenter_esp = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_HOST_STATE, VMCS_WIDTH_NATURAL, 8);
        Fields->natural_state.ia32_sysenter_eip = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_HOST_STATE, VMCS_WIDTH_NATURAL, 9);
        Fields->natural_state.rsp = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_HOST_STATE, VMCS_WIDTH_NATURAL, 10);
        Fields->natural_state.rip = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_HOST_STATE, VMCS_WIDTH_NATURAL, 11);

        /* 64 bit */

        Fields->natural_state.ia32_perf_global_ctrl = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_HOST_STATE, VMCS_WIDTH_64, 2);

        /* 16 bit */

        Fields->word_state.es_selector = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_HOST_STATE, VMCS_WIDTH_16, 0);
        Fields->word_state.cs_selector = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_HOST_STATE, VMCS_WIDTH_16, 1);
        Fields->word_state.ss_selector = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_HOST_STATE, VMCS_WIDTH_16, 2);
        Fields->word_state.ds_selector = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_HOST_STATE, VMCS_WIDTH_16, 3);
        Fields->word_state.fs_selector = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_HOST_STATE, VMCS_WIDTH_16, 4);
        Fields->word_state.gs_selector = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_HOST_STATE, VMCS_WIDTH_16, 5);
        Fields->word_state.tr_selector = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_HOST_STATE, VMCS_WIDTH_16, 6);

        /* 32 bit */

        Fields->dword_state.ia32_sysenter_cs = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_HOST_STATE, VMCS_WIDTH_32, 0);
}

STATIC
VOID
EncodeVmcsControlStateFields(
        _In_ PVMCS_CONTROL_STATE_FIELDS Fields)
{
        /* natural state */

        Fields->natural_state.cr0_guest_host_mask = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_CONTROL, VMCS_WIDTH_NATURAL, 0);
        Fields->natural_state.cr4_guest_host_mask = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_CONTROL, VMCS_WIDTH_NATURAL, 1);
        Fields->natural_state.cr0_read_shadow = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_CONTROL, VMCS_WIDTH_NATURAL, 2);
        Fields->natural_state.cr4_read_shadow = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_CONTROL, VMCS_WIDTH_NATURAL, 3);
        Fields->natural_state.cr3_target_value_0 = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_CONTROL, VMCS_WIDTH_NATURAL, 4);
        Fields->natural_state.cr3_target_value_1 = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_CONTROL, VMCS_WIDTH_NATURAL, 5);
        Fields->natural_state.cr3_target_value_2 = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_CONTROL, VMCS_WIDTH_NATURAL, 6);
        Fields->natural_state.cr3_target_value_3 = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_CONTROL, VMCS_WIDTH_NATURAL, 7);

        /* 64bit state */

        Fields->qword_state.io_bitmap_a_address = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_CONTROL, VMCS_WIDTH_64, 0);
        Fields->qword_state.io_bitmap_b_address = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_CONTROL, VMCS_WIDTH_64, 1);
        Fields->qword_state.msr_bitmap_address = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_CONTROL, VMCS_WIDTH_64, 2);
        Fields->qword_state.vmexit_msr_store_address = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_CONTROL, VMCS_WIDTH_64, 3);
        Fields->qword_state.vmexit_msr_load_address = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_CONTROL, VMCS_WIDTH_64, 4);
        Fields->qword_state.vmentry_msr_load_address = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_CONTROL, VMCS_WIDTH_64, 5);
        Fields->qword_state.executive_vmcs_pointer = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_CONTROL, VMCS_WIDTH_64, 6);
        Fields->qword_state.pml_address = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_CONTROL, VMCS_WIDTH_64, 7);
        Fields->qword_state.tsc_offset = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_CONTROL, VMCS_WIDTH_64, 8);
        Fields->qword_state.virtual_apic_address = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_CONTROL, VMCS_WIDTH_64, 9);
        Fields->qword_state.apic_access_address = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_CONTROL, VMCS_WIDTH_64, 10);
        Fields->qword_state.posted_interrupt_descriptor_address = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_CONTROL, VMCS_WIDTH_64, 11);
        Fields->qword_state.vmfunc_controls = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_CONTROL, VMCS_WIDTH_64, 12);
        Fields->qword_state.ept_pointer = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_CONTROL, VMCS_WIDTH_64, 13);
        Fields->qword_state.eoi_exit_bitmap_0 = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_CONTROL, VMCS_WIDTH_64, 14);
        Fields->qword_state.eoi_exit_bitmap_1 = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_CONTROL, VMCS_WIDTH_64, 15);
        Fields->qword_state.eoi_exit_bitmap_2 = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_CONTROL, VMCS_WIDTH_64, 16);
        Fields->qword_state.eoi_exit_bitmap_3 = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_CONTROL, VMCS_WIDTH_64, 17);
        Fields->qword_state.ept_pointer_list_address = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_CONTROL, VMCS_WIDTH_64, 18);
        Fields->qword_state.vmread_bitmap_address = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_CONTROL, VMCS_WIDTH_64, 19);
        Fields->qword_state.vmwrite_bitmap_address = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_CONTROL, VMCS_WIDTH_64, 20);
        Fields->qword_state.virtualization_exception_info_address = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_CONTROL, VMCS_WIDTH_64, 21);
        Fields->qword_state.xss_exiting_bitmap = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_CONTROL, VMCS_WIDTH_64, 22);
        Fields->qword_state.encls_exiting_bitmap = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_CONTROL, VMCS_WIDTH_64, 23);
        Fields->qword_state.tsc_multiplier = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_CONTROL, VMCS_WIDTH_64, 25);

        /* 32 bit state */

        Fields->dword_state.pin_based_vm_execution_controls = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_CONTROL, VMCS_WIDTH_32, 0);
        Fields->dword_state.processor_based_vm_execution_controls = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_CONTROL, VMCS_WIDTH_32, 1);
        Fields->dword_state.exception_bitmap = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_CONTROL, VMCS_WIDTH_32, 2);
        Fields->dword_state.pagefault_error_code_mask = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_CONTROL, VMCS_WIDTH_32, 3);
        Fields->dword_state.pagefault_error_code_match = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_CONTROL, VMCS_WIDTH_32, 4);
        Fields->dword_state.cr3_target_count = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_CONTROL, VMCS_WIDTH_32, 5);
        Fields->dword_state.vmexit_controls = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_CONTROL, VMCS_WIDTH_32, 6);
        Fields->dword_state.vmexit_msr_store_count = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_CONTROL, VMCS_WIDTH_32, 7);
        Fields->dword_state.vmexit_msr_load_count = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_CONTROL, VMCS_WIDTH_32, 8);
        Fields->dword_state.vmentry_controls = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_CONTROL, VMCS_WIDTH_32, 9);
        Fields->dword_state.vmentry_msr_load_count = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_CONTROL, VMCS_WIDTH_32, 10);
        Fields->dword_state.vmentry_interruption_info = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_CONTROL, VMCS_WIDTH_32, 11);
        Fields->dword_state.vmentry_exception_error_code = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_CONTROL, VMCS_WIDTH_32, 12);
        Fields->dword_state.vmentry_instruction_length = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_CONTROL, VMCS_WIDTH_32, 13);
        Fields->dword_state.tpr_threshold = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_CONTROL, VMCS_WIDTH_32, 14);
        Fields->dword_state.secondary_processor_based_vm_execution_controls = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_CONTROL, VMCS_WIDTH_32, 15);
        Fields->dword_state.ple_gap = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_CONTROL, VMCS_WIDTH_32, 16);
        Fields->dword_state.ple_window = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_CONTROL, VMCS_WIDTH_32, 17);

        /* 16 bit state */

        Fields->word_state.virtual_processor_identifier = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_CONTROL, VMCS_WIDTH_16, 0);
        Fields->word_state.posted_interrupt_notification_vector = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_CONTROL, VMCS_WIDTH_16, 1);
        Fields->word_state.eptp_index = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_CONTROL, VMCS_WIDTH_16, 2);
}

STATIC
VOID
VmcsWriteHostStateFields(
        _In_ PVIRTUAL_MACHINE_STATE GuestState
)
{
        __vmx_vmwrite(host_state_fields.word_state.es_selector, __reades() & 0xF8);
        __vmx_vmwrite(host_state_fields.word_state.cs_selector, __readcs() & 0xF8);
        __vmx_vmwrite(host_state_fields.word_state.ss_selector, __readss() & 0xF8);
        __vmx_vmwrite(host_state_fields.word_state.ds_selector, __readds() & 0xF8);
        __vmx_vmwrite(host_state_fields.word_state.fs_selector, __readfs() & 0xF8);
        __vmx_vmwrite(host_state_fields.word_state.gs_selector, __readgs() & 0xF8);
        __vmx_vmwrite(host_state_fields.word_state.tr_selector, __readtr() & 0xF8);

        __vmx_vmwrite(host_state_fields.natural_state.cr0, __readcr0());
        __vmx_vmwrite(host_state_fields.natural_state.cr3, __readcr3());
        __vmx_vmwrite(host_state_fields.natural_state.cr4, __readcr4());

        __vmx_vmwrite(host_state_fields.natural_state.gdtr_base, __readgdtbase());
        __vmx_vmwrite(host_state_fields.natural_state.idtr_base, __readidtbase());

        __vmx_vmwrite(host_state_fields.natural_state.rsp, GuestState->vmm_stack + VMM_STACK_SIZE - 1);
        __vmx_vmwrite(host_state_fields.natural_state.rip, VmexitHandler);
        
        SEGMENT_SELECTOR selector = { 0 };

        GetSegmentDescriptor(&selector, __readtr(), (PUCHAR)__readgdtbase());
        __vmx_vmwrite(HOST_TR_BASE, selector.BASE);

        __vmx_vmwrite(HOST_FS_BASE, __readmsr(MSR_FS_BASE));
        __vmx_vmwrite(HOST_GS_BASE, __readmsr(MSR_GS_BASE));

        __vmx_vmwrite(HOST_IA32_SYSENTER_CS, __readmsr(MSR_IA32_SYSENTER_CS));
        __vmx_vmwrite(HOST_IA32_SYSENTER_EIP, __readmsr(MSR_IA32_SYSENTER_EIP));
        __vmx_vmwrite(HOST_IA32_SYSENTER_ESP, __readmsr(MSR_IA32_SYSENTER_ESP));
}

STATIC
VOID
VmcsWriteGuestStateFields(
        _In_ PVOID StackPointer
)
{
        __vmx_vmwrite(guest_state_fields.qword_state.vmcs_link_pointer, ~0ull);

        __vmx_vmwrite(GUEST_IA32_DEBUGCTL_HIGH, __readmsr(MSR_IA32_DEBUGCTL) >> 32);
        __vmx_vmwrite(guest_state_fields.qword_state.debug_control, __readmsr(MSR_IA32_DEBUGCTL) & 0xFFFFFFFF);

        __vmx_fill_selector_data(__readgdtbase(), ES, __reades());
        __vmx_fill_selector_data(__readgdtbase(), CS, __readcs());
        __vmx_fill_selector_data(__readgdtbase(), SS, __readss());
        __vmx_fill_selector_data(__readgdtbase(), DS, __readds());
        __vmx_fill_selector_data(__readgdtbase(), FS, __readfs());
        __vmx_fill_selector_data(__readgdtbase(), GS, __readgs());
        __vmx_fill_selector_data(__readgdtbase(), LDTR, __readldtr());
        __vmx_fill_selector_data(__readgdtbase(), TR, __readtr());

        __vmx_vmwrite(guest_state_fields.natural_state.cr0, __readcr0());
        __vmx_vmwrite(guest_state_fields.natural_state.cr3, __readcr3());
        __vmx_vmwrite(guest_state_fields.natural_state.cr4, __readcr4());
        __vmx_vmwrite(guest_state_fields.natural_state.dr7, 0x400);

        __vmx_vmwrite(guest_state_fields.natural_state.gdtr_base, __readgdtbase());
        __vmx_vmwrite(guest_state_fields.natural_state.idtr_base, __readidtbase());

        __vmx_vmwrite(guest_state_fields.dword_state.gdtr_limit, __segmentlimit(__readgdtbase));
        __vmx_vmwrite(guest_state_fields.dword_state.idtr_limit, __segmentlimit(__readidtbase));

        __vmx_vmwrite(guest_state_fields.natural_state.rflags, __readrflags());

        __vmx_vmwrite(guest_state_fields.dword_state.sysenter_cs, __readmsr(MSR_IA32_SYSENTER_CS));
        __vmx_vmwrite(guest_state_fields.natural_state.sysenter_eip, __readmsr(MSR_IA32_SYSENTER_EIP));
        __vmx_vmwrite(guest_state_fields.natural_state.sysenter_esp, __readmsr(MSR_IA32_SYSENTER_ESP));
        __vmx_vmwrite(guest_state_fields.natural_state.fs_base, __readmsr(MSR_FS_BASE));
        __vmx_vmwrite(guest_state_fields.natural_state.gs_base, __readmsr(MSR_GS_BASE));

        __vmx_vmwrite(guest_state_fields.natural_state.rsp, StackPointer);
        __vmx_vmwrite(guest_state_fields.natural_state.rip, VmxRestoreState);
}

STATIC
VOID
VmcsWriteControlStateFields(
        _In_ PVIRTUAL_MACHINE_STATE GuestState
)
{
        /*
        * ActivateSecondaryControls activates the secondary processor-based VM-execution controls.
        * If UseMsrBitmaps is not set, all RDMSR and WRMSR instructions cause vm-exits. 
        */
        IA32_VMX_PROCBASED_CTLS_REGISTER proc_ctls = { 0 };
        proc_ctls.ActivateSecondaryControls = TRUE;
        proc_ctls.UseMsrBitmaps = TRUE;

        __vmx_vmwrite(CPU_BASED_VM_EXEC_CONTROL, 
                AdjustMsrControl((UINT32)proc_ctls.AsUInt, MSR_IA32_VMX_PROCBASED_CTLS));

        /*
        * Ensure RDTSCP, INVPCID and XSAVES/XRSTORS do not raise an invalid opcode exception.
        */
        IA32_VMX_PROCBASED_CTLS2_REGISTER proc_ctls2 = { 0 };
        proc_ctls2.EnableRdtscp = TRUE;
        proc_ctls2.EnableInvpcid = TRUE;
        proc_ctls2.EnableXsaves = TRUE;

        __vmx_vmwrite(SECONDARY_VM_EXEC_CONTROL, 
                AdjustMsrControl((UINT32)proc_ctls2.AsUInt, MSR_IA32_VMX_PROCBASED_CTLS2));

        /*
        * Lets not force a vmexit on any external interrupts
        */
        IA32_VMX_PINBASED_CTLS_REGISTER pin_ctls = { 0 };

        __vmx_vmwrite(PIN_BASED_VM_EXEC_CONTROL,  
                AdjustMsrControl((UINT32)pin_ctls.AsUInt, MSR_IA32_VMX_PINBASED_CTLS));

        /*
        * Ensure we acknowledge interrupts on VMEXIT and are in 64 bit mode.
        */
        IA32_VMX_EXIT_CTLS_REGISTER exit_ctls = { 0 };
        exit_ctls.AcknowledgeInterruptOnExit = TRUE;
        exit_ctls.HostAddressSpaceSize = TRUE;

        __vmx_vmwrite(VM_EXIT_CONTROLS, 
                AdjustMsrControl((UINT32)exit_ctls.AsUInt, MSR_IA32_VMX_EXIT_CTLS));

        /*
        * Ensure we are in 64bit mode on VMX entry.
        */
        IA32_VMX_ENTRY_CTLS_REGISTER entry_ctls = { 0 };
        entry_ctls.Ia32EModeGuest = TRUE;

        __vmx_vmwrite(VM_ENTRY_CONTROLS, 
                AdjustMsrControl((UINT32)entry_ctls.AsUInt, MSR_IA32_VMX_ENTRY_CTLS));

        __vmx_vmwrite(control_state_fields.qword_state.msr_bitmap_address, GuestState->msr_bitmap_pa);
}

NTSTATUS
SetupVmcs(
        _In_ PVIRTUAL_MACHINE_STATE GuestState,
        _In_ PVOID StackPointer
)
{
        EncodeVmcsControlStateFields(&control_state_fields);
        EncodeVmcsGuestStateFields(&guest_state_fields);
        EncodeVmcsHostStateFields(&host_state_fields);

        if (__vmx_vmclear(&GuestState->vmcs_region_pa) != VMX_OK)
        {
                DEBUG_ERROR("Unable to clear the vmcs region");
                return STATUS_ABANDONED;
        }

        if (__vmx_vmptrld(&GuestState->vmcs_region_pa) != VMX_OK)
        {
                DEBUG_ERROR("vmptrld failed");
                return STATUS_ABANDONED;
        }

        VmcsWriteControlStateFields(GuestState);
        VmcsWriteGuestStateFields(StackPointer);
        VmcsWriteHostStateFields(GuestState);
        //SetupVmcsAndVirtualizeMachine(GuestState, StackPointer);
        return STATUS_SUCCESS;
}

VOID
ResumeToNextInstruction(
        _In_ UINT64 InstructionOffset
)
{
        PVOID current_rip = NULL;
        ULONG exit_instruction_length = 0;

        /*
        * Advance the guest RIP by the size of the exit-causing instruction
        */
        __vmx_vmread(GUEST_RIP, &current_rip);
        __vmx_vmread(VM_EXIT_INSTRUCTION_LEN, &exit_instruction_length);
        __vmx_vmwrite(GUEST_RIP, (UINT64)current_rip + exit_instruction_length + InstructionOffset);
}

VOID
VmResumeInstruction()
{
        __vmx_vmresume();

        /* If vmresume succeeds we won't reach here */

        UINT64 error = 0;

        __vmx_vmread(VM_INSTRUCTION_ERROR, &error);
        __vmx_off();

        DEBUG_ERROR("VMRESUME Error : 0x%llx", error);
}

STATIC
VOID
DispatchExitReasonControlRegisterAccess(
        _In_ PGUEST_REGS GuestState
)
{
        INT64 rsp = 0;
        ULONG exit_qualification = 0;

        __vmx_vmread(EXIT_QUALIFICATION, &exit_qualification);

        PMOV_CR_QUALIFICATION data = (PMOV_CR_QUALIFICATION)&exit_qualification;
        PUINT64 register_ptr = (PUINT64)&GuestState->rax + data->Fields.Register;

        if (data->Fields.Register == 4)
        {
                __vmx_vmread(GUEST_RSP, &rsp);
                *register_ptr = rsp;
        }

        switch (data->Fields.AccessType)
        {
        case TYPE_MOV_TO_CR:
        {
                switch (data->Fields.ControlRegister)
                {
                case 0:
                        __vmx_vmwrite(GUEST_CR0, *register_ptr);
                        __vmx_vmwrite(CR0_READ_SHADOW, *register_ptr);
                        break;
                case 3:
                        __vmx_vmwrite(GUEST_CR3, (*register_ptr & ~(1ULL << 63)));
                        break;
                case 4:
                        __vmx_vmwrite(GUEST_CR4, *register_ptr);
                        __vmx_vmwrite(CR4_READ_SHADOW, *register_ptr);
                        break;
                default:
                        DEBUG_LOG("Register not supported.");
                        break;
                }
        }
        break;

        case TYPE_MOV_FROM_CR:
        {
                switch (data->Fields.ControlRegister)
                {
                case 0:
                        __vmx_vmread(GUEST_CR0, register_ptr);
                        break;
                case 3:
                        __vmx_vmread(GUEST_CR3, register_ptr);
                        break;
                case 4:
                        __vmx_vmread(GUEST_CR4, register_ptr);
                        break;
                default:
                        DEBUG_LOG("Register not supported.");
                        break;
                }
        }
        break;

        default:
                break;
        }
}

STATIC
VOID
DispatchExitReasonInvd(
        _In_ PGUEST_REGS GuestState
)
{
        /* this is how hyper-v performs their invd */
        __wbinvd();
}

STATIC
VOID
DispatchExitReasonCPUID(
        _In_ PGUEST_REGS GuestState
)
{
        INT32 cpuid_result[4];

        __cpuidex(cpuid_result, (INT32)GuestState->rax, (INT32)GuestState->rcx);

        GuestState->rax = cpuid_result[0];
        GuestState->rbx = cpuid_result[1];
        GuestState->rcx = cpuid_result[2];
        GuestState->rdx = cpuid_result[3];
}

VOID
VmExitDispatcher(
        _In_ PGUEST_REGS GuestState
)
{
        UINT64 additional_rip_offset = 0;
        ULONG exit_reason = 0;
        ULONG exit_qualification = 0;
        UINT64 current_rip = 0;
        ULONG exit_instruction_length = 0;
        UINT64 increment_size = 0;
        ZyanStatus status = ZYAN_STATUS_ACCESS_DENIED;

        __vmx_vmread(VM_EXIT_REASON, &exit_reason);
        __vmx_vmread(EXIT_QUALIFICATION, &exit_qualification);
        __vmx_vmread(GUEST_RIP, &current_rip);
        __vmx_vmread(VM_EXIT_INSTRUCTION_LEN, &exit_instruction_length);

        switch (exit_reason)
        {
        case EXIT_REASON_VMCLEAR:
        case EXIT_REASON_VMPTRLD:
        case EXIT_REASON_VMPTRST:
        case EXIT_REASON_VMREAD:
        case EXIT_REASON_VMRESUME:
        case EXIT_REASON_VMWRITE:
        case EXIT_REASON_VMXOFF:
        case EXIT_REASON_VMXON:
        case EXIT_REASON_VMLAUNCH:
        case EXIT_REASON_HLT:
        case EXIT_REASON_EXCEPTION_NMI:
        case EXIT_REASON_CPUID: { DispatchExitReasonCPUID(GuestState); break; }
        case EXIT_REASON_INVD: { DispatchExitReasonInvd(GuestState); break; }
        case EXIT_REASON_VMCALL:
        case EXIT_REASON_CR_ACCESS: { DispatchExitReasonControlRegisterAccess(GuestState); break; }
        case EXIT_REASON_MSR_READ:
        case EXIT_REASON_MSR_WRITE:
        case EXIT_REASON_EPT_VIOLATION:
        default: { break; }
        }

        /*
        * Once we have processed the initial instruction causing the vmexit, we can
        * translate the next instruction. Once decoded, if its a vm-exit causing instruction
        * we can process that instruction and then advance the rip by the size of the 2 
        * exit-inducing instructions - saving us 1 vm exit (2 minus 1 = 1).
        */

        //HandleFutureInstructions(
        //        (PVOID)((UINT64)current_rip + exit_instruction_length),
        //        GuestState,
        //        &increment_size
        //);

        //ResumeToNextInstruction(exit_instruction_length + increment_size);

        status = HandleFutureInstructions(
                (PVOID)(current_rip + exit_instruction_length),
                GuestState,
                &additional_rip_offset
        );

        ResumeToNextInstruction(additional_rip_offset);
}
