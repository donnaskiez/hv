#include "vmx.h"
#include "ept.h"
#include "common.h"

VIRTUAL_MACHINE_STATE* vmm_state;
ULONG                     proc_count;

VMCS_GUEST_STATE_FIELDS   guest_state_fields = { 0 };
VMCS_HOST_STATE_FIELDS    host_state_fields = { 0 };
VMCS_CONTROL_STATE_FIELDS control_state_fields = { 0 };

#define STATIC static
#define VOID void

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
        CPUID Data = { 0 };

        //
        // Check for the VMX bit
        //
        __cpuid((int*)&Data, 1);
        if ((Data.ecx & (1 << 5)) == 0)
                return FALSE;

        IA32_FEATURE_CONTROL_MSR Control = { 0 };
        Control.bit_address = __readmsr(MSR_IA32_FEATURE_CONTROL);

        //
        // BIOS lock check
        //
        if (Control.bits.Lock == 0)
        {
                Control.bits.Lock = TRUE;
                Control.bits.EnableVmxon = TRUE;
                __writemsr(MSR_IA32_FEATURE_CONTROL, Control.bit_address);
        }
        else if (Control.bits.EnableVmxon == FALSE)
        {
                DbgPrint("[*] VMX locked off in BIOS");
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
BOOLEAN
hvdbgAllocateVmcsRegion(VIRTUAL_MACHINE_STATE* GuestState)
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

BOOLEAN
hvdbgAllocateVmxonRegion(VIRTUAL_MACHINE_STATE* GuestState)
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

VOID
InitiateVmx()
{
        if (!IsVmxSupported())
        {
                DbgPrint("[*] VMX is not supported in this machine !\n");
                return;
        }

        PAGED_CODE();

        vmm_state = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(VIRTUAL_MACHINE_STATE) * KeQueryActiveProcessorCount(0), POOLTAG);
        proc_count = KeQueryActiveProcessorCount(0);

        if (!vmm_state)
                return;

        for (size_t index = 0; index < proc_count; index++)
        {
                KeSetSystemAffinityThread(1ull << index);
                hvdbgEnableVmxOperationOnCore();
                hvdbgAllocateVmxonRegion(&vmm_state[index]);
                hvdbgAllocateVmcsRegion(&vmm_state[index]);
                DEBUG_LOG("VMX operation initiated on core: %lx", (ULONG)index);
        }
}

VOID
LaunchVm(int ProcessorID, PEPTP EPTP)
{
        KeSetSystemAffinityThread(1ull << ProcessorID);

        DbgPrint("[*]\t\tCurrent thread is executing in %d th logical processor.\n", ProcessorID);

        PAGED_CODE();

        vmm_state[ProcessorID].vmm_stack = ExAllocatePool2(POOL_FLAG_NON_PAGED, VMM_STACK_SIZE, POOLTAG);

        if (!vmm_state[ProcessorID].vmm_stack)
        {
                DbgPrint("[*] Error in allocating VMM Stack.\n");
                return;
        }

        vmm_state[ProcessorID].msr_bitmap_va = MmAllocateNonCachedMemory(PAGE_SIZE); // should be aligned

        if (!vmm_state[ProcessorID].msr_bitmap_va)
        {
                DbgPrint("[*] Error in allocating MSRBitMap.\n");
                return;
        }
        RtlSecureZeroMemory(vmm_state[ProcessorID].msr_bitmap_va, PAGE_SIZE);

        vmm_state[ProcessorID].msr_bitmap_pa = MmGetPhysicalAddress(vmm_state[ProcessorID].msr_bitmap_va).QuadPart;

        SetupVmcs(&vmm_state[ProcessorID], EPTP);

        __vmx_savestate();
        __vmx_vmlaunch();

        /*
        * If vmlaunch succeeds, we will never get here.
        */
        ULONG64 ErrorCode = 0;
        __vmx_vmread(VM_INSTRUCTION_ERROR, &ErrorCode);
        __vmx_off();
        DbgPrint("[*] VMLAUNCH Error : 0x%llx\n", ErrorCode);
        __debugbreak();

ReturnWithoutError:
        __vmx_off();
        DbgPrint("[*] VMXOFF Executed Successfully. !\n");

        return TRUE;

        //
        // Return With Error
        //
ErrorReturn:
        DbgPrint("[*] Fail to setup VMCS !\n");
        return FALSE;
}

VOID
TerminateVmx()
{
        DbgPrint("\n[*] Terminating VMX...\n");

        for (size_t i = 0; i < proc_count; i++)
        {
                KeSetSystemAffinityThread(1ull << i);
                DbgPrint("\t\tCurrent thread is executing in %d th logical processor.\n", i);

                __vmx_off();
                MmFreeContiguousMemory(MmGetPhysicalAddress(vmm_state[i].vmxon_region_pa).QuadPart);
                MmFreeContiguousMemory(MmGetPhysicalAddress(vmm_state[i].vmcs_region_pa).QuadPart);
        }

        DbgPrint("[*] VMX Operation turned off successfully. \n");
}

UINT64
VmptrstInstruction()
{
        PHYSICAL_ADDRESS vmcspa;
        vmcspa.QuadPart = 0;
        __vmx_vmptrst((unsigned __int64*)&vmcspa);

        DbgPrint("[*] VMPTRST %llx\n", vmcspa);

        return 0;
}

BOOLEAN
GetSegmentDescriptor(
        PSEGMENT_SELECTOR SegmentSelector,
        USHORT            Selector,
        PUCHAR            GdtBase
)
{
        PSEGMENT_DESCRIPTOR SegDesc;

        if (!SegmentSelector)
                return FALSE;

        if (Selector & 0x4)
                return FALSE;

        SegDesc = (PSEGMENT_DESCRIPTOR)((PUCHAR)GdtBase + (Selector & ~0x7));

        SegmentSelector->SEL = Selector;
        SegmentSelector->BASE = SegDesc->BASE0 | SegDesc->BASE1 << 16 | SegDesc->BASE2 << 24;
        SegmentSelector->LIMIT = SegDesc->LIMIT0 | (SegDesc->LIMIT1ATTR1 & 0xf) << 16;
        SegmentSelector->ATTRIBUTES.UCHARs = SegDesc->ATTR0 | (SegDesc->LIMIT1ATTR1 & 0xf0) << 4;

        if (!(SegDesc->ATTR0 & 0x10))
        {
                ULONG64 Tmp;
                // this is a TSS or callgate etc, save the base high part
                Tmp = (*(PULONG64)((PUCHAR)SegDesc + 8));
                SegmentSelector->BASE = (SegmentSelector->BASE & 0xffffffff) | (Tmp << 32);
        }

        if (SegmentSelector->ATTRIBUTES.Fields.G)
        {
                // 4096-bit granularity is enabled for this segment, scale the limit
                SegmentSelector->LIMIT = (SegmentSelector->LIMIT << 12) + 0xfff;
        }

        return TRUE;
}

BOOLEAN
SetGuestSelector(PVOID GDT_Base, ULONG Segment_Register, USHORT Selector)
{
        SEGMENT_SELECTOR SegmentSelector = { 0 };
        ULONG            uAccessRights;

        GetSegmentDescriptor(&SegmentSelector, Selector, GDT_Base);
        uAccessRights = ((PUCHAR)&SegmentSelector.ATTRIBUTES)[0] + (((PUCHAR)&SegmentSelector.ATTRIBUTES)[1] << 12);

        if (!Selector)
                uAccessRights |= 0x10000;

        __vmx_vmwrite(GUEST_ES_SELECTOR + Segment_Register * 2, Selector);
        __vmx_vmwrite(GUEST_ES_LIMIT + Segment_Register * 2, SegmentSelector.LIMIT);
        __vmx_vmwrite(GUEST_ES_AR_BYTES + Segment_Register * 2, uAccessRights);
        __vmx_vmwrite(GUEST_ES_BASE + Segment_Register * 2, SegmentSelector.BASE);

        return TRUE;
}

ULONG
AdjustControls(
        _In_ ULONG Ctl,
        _In_ ULONG  Msr
)
{
        MSR MsrValue = { 0 };

        MsrValue.Content = __readmsr(Msr);
        Ctl &= MsrValue.High; /* bit == 0 in high word ==> must be zero */
        Ctl |= MsrValue.Low;  /* bit == 1 in low word  ==> must be one  */
        return Ctl;
}

VOID
__vmx_fill_selector_data(
        _In_ PVOID  GdtBase,
        _In_ ULONG  Segreg,
        _In_ USHORT Selector)
{
        SEGMENT_SELECTOR SegmentSelector = { 0 };
        ULONG            AccessRights;

        GetSegmentDescriptor(&SegmentSelector, Selector, GdtBase);
        AccessRights = ((PUCHAR)&SegmentSelector.ATTRIBUTES)[0] + (((PUCHAR)&SegmentSelector.ATTRIBUTES)[1] << 12);

        if (!Selector)
                AccessRights |= 0x10000;

        __vmx_vmwrite(GUEST_ES_SELECTOR + Segreg * 2, Selector);
        __vmx_vmwrite(GUEST_ES_LIMIT + Segreg * 2, SegmentSelector.LIMIT);
        __vmx_vmwrite(GUEST_ES_AR_BYTES + Segreg * 2, AccessRights);
        __vmx_vmwrite(GUEST_ES_BASE + Segreg * 2, SegmentSelector.BASE);
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

BOOLEAN
SetupVmcs(VIRTUAL_MACHINE_STATE* GuestState, PEPTP EPTP)
{
        BOOLEAN Status = FALSE;

        // Load Extended Page Table Pointer
        //__vmx_vmwrite(EPT_POINTER, EPTP->All);

        ULONG64          gdt_base = __readgdtbase();
        SEGMENT_SELECTOR SegmentSelector = { 0 };

        EncodeVmcsControlStateFields(&control_state_fields);
        EncodeVmcsGuestStateFields(&guest_state_fields);
        EncodeVmcsHostStateFields(&host_state_fields);

        if (__vmx_vmclear(&GuestState->vmcs_region_pa) != VMX_OK ||
                __vmx_vmptrld(&GuestState->vmcs_region_pa))
        {
                DEBUG_LOG("Unable to clear the vmcs region");
                return STATUS_ABANDONED;
        }

        DEBUG_LOG("es selector mine: %llx, es selector intel: %llx", (UINT64)host_state_fields.word_state.es_selector, (UINT64)HOST_ES_SELECTOR);

        __vmx_vmwrite(host_state_fields.word_state.es_selector, __reades() & 0xF8);
        __vmx_vmwrite(host_state_fields.word_state.cs_selector, __readcs() & 0xF8);
        __vmx_vmwrite(host_state_fields.word_state.ss_selector, __readss() & 0xF8);
        __vmx_vmwrite(host_state_fields.word_state.ds_selector, __readds() & 0xF8);
        __vmx_vmwrite(host_state_fields.word_state.fs_selector, __readfs() & 0xF8);
        __vmx_vmwrite(host_state_fields.word_state.gs_selector, __readgs() & 0xF8);
        __vmx_vmwrite(host_state_fields.word_state.tr_selector, __readtr() & 0xF8);

        __vmx_vmwrite(guest_state_fields.qword_state.vmcs_link_pointer, ~0ULL);

        __vmx_vmwrite(guest_state_fields.qword_state.debug_control, __readmsr(MSR_IA32_DEBUGCTL) & 0xFFFFFFFF);
        __vmx_vmwrite(GUEST_IA32_DEBUGCTL_HIGH, __readmsr(MSR_IA32_DEBUGCTL) >> 32);

        /* Time-stamp counter offset */
        __vmx_vmwrite(control_state_fields.qword_state.tsc_offset, 0);
        __vmx_vmwrite(TSC_OFFSET_HIGH, 0);
        __vmx_vmwrite(control_state_fields.dword_state.pagefault_error_code_mask, 0);
        __vmx_vmwrite(control_state_fields.dword_state.pagefault_error_code_match, 0);
        __vmx_vmwrite(control_state_fields.dword_state.vmexit_msr_load_count, 0);
        __vmx_vmwrite(control_state_fields.dword_state.vmexit_msr_store_count, 0);
        __vmx_vmwrite(control_state_fields.dword_state.vmentry_msr_load_count, 0);
        __vmx_vmwrite(control_state_fields.dword_state.vmentry_interruption_info, 0);

        __vmx_fill_selector_data(gdt_base, ES, __reades());
        __vmx_fill_selector_data(gdt_base, CS, __readcs());
        __vmx_fill_selector_data(gdt_base, SS, __readss());
        __vmx_fill_selector_data(gdt_base, DS, __readds());
        __vmx_fill_selector_data(gdt_base, FS, __readfs());
        __vmx_fill_selector_data(gdt_base, GS, __readgs());
        __vmx_fill_selector_data(gdt_base, LDTR, __readldtr());
        __vmx_fill_selector_data(gdt_base, TR, __readtr());

        __vmx_vmwrite(guest_state_fields.natural_state.fs_base, __readmsr(MSR_FS_BASE));
        __vmx_vmwrite(guest_state_fields.natural_state.gs_base, __readmsr(MSR_GS_BASE));

        __vmx_vmwrite(GUEST_INTERRUPTIBILITY_INFO, 0);
        __vmx_vmwrite(GUEST_ACTIVITY_STATE, 0); // Active state

        __vmx_vmwrite(CPU_BASED_VM_EXEC_CONTROL, AdjustControls(CPU_BASED_HLT_EXITING | CPU_BASED_ACTIVATE_SECONDARY_CONTROLS, MSR_IA32_VMX_PROCBASED_CTLS));
        __vmx_vmwrite(SECONDARY_VM_EXEC_CONTROL, AdjustControls(CPU_BASED_CTL2_RDTSCP /* | CPU_BASED_CTL2_ENABLE_EPT*/, MSR_IA32_VMX_PROCBASED_CTLS2));

        __vmx_vmwrite(PIN_BASED_VM_EXEC_CONTROL, AdjustControls(0, MSR_IA32_VMX_PINBASED_CTLS));
        __vmx_vmwrite(VM_EXIT_CONTROLS, AdjustControls(VM_EXIT_IA32E_MODE | VM_EXIT_ACK_INTR_ON_EXIT, MSR_IA32_VMX_EXIT_CTLS));
        __vmx_vmwrite(VM_ENTRY_CONTROLS, AdjustControls(VM_ENTRY_IA32E_MODE, MSR_IA32_VMX_ENTRY_CTLS));

        __vmx_vmwrite(control_state_fields.dword_state.cr3_target_count, 0);
        __vmx_vmwrite(control_state_fields.natural_state.cr3_target_value_0, 0);
        __vmx_vmwrite(control_state_fields.natural_state.cr3_target_value_1, 0);
        __vmx_vmwrite(control_state_fields.natural_state.cr3_target_value_2, 0);
        __vmx_vmwrite(control_state_fields.natural_state.cr3_target_value_3, 0);

        __vmx_vmwrite(guest_state_fields.natural_state.cr0, __readcr0());
        __vmx_vmwrite(guest_state_fields.natural_state.cr3, __readcr3());
        __vmx_vmwrite(guest_state_fields.natural_state.cr4, __readcr4());

        __vmx_vmwrite(guest_state_fields.natural_state.dr7, 0x400);

        __vmx_vmwrite(host_state_fields.natural_state.cr0, __readcr0());
        __vmx_vmwrite(host_state_fields.natural_state.cr3, __readcr3());
        __vmx_vmwrite(host_state_fields.natural_state.cr4, __readcr4());

        __vmx_vmwrite(guest_state_fields.natural_state.gdtr_base, __readgdtbase());
        __vmx_vmwrite(guest_state_fields.natural_state.idtr_base, __readidtbase());
        __vmx_vmwrite(guest_state_fields.dword_state.gdtr_limit, __getgdtlimit());
        __vmx_vmwrite(guest_state_fields.dword_state.idtr_limit, __getidtlimit());

        __vmx_vmwrite(guest_state_fields.natural_state.rflags, __readrflags());

        __vmx_vmwrite(guest_state_fields.dword_state.sysenter_cs, __readmsr(MSR_IA32_SYSENTER_CS));
        __vmx_vmwrite(guest_state_fields.natural_state.sysenter_eip, __readmsr(MSR_IA32_SYSENTER_EIP));
        __vmx_vmwrite(guest_state_fields.natural_state.sysenter_esp, __readmsr(MSR_IA32_SYSENTER_ESP));

        GetSegmentDescriptor(&SegmentSelector, __readtr(), (PUCHAR)__readgdtbase());

        __vmx_vmwrite(host_state_fields.natural_state.tr_base, SegmentSelector.BASE);
        __vmx_vmwrite(host_state_fields.natural_state.fs_base, __readmsr(MSR_FS_BASE));
        __vmx_vmwrite(host_state_fields.natural_state.gs_base, __readmsr(MSR_GS_BASE));
        __vmx_vmwrite(host_state_fields.natural_state.gdtr_base, __readgdtbase());
        __vmx_vmwrite(host_state_fields.natural_state.idtr_base, __readidtbase());

        __vmx_vmwrite(host_state_fields.dword_state.ia32_sysenter_cs, __readmsr(MSR_IA32_SYSENTER_CS));
        __vmx_vmwrite(host_state_fields.natural_state.ia32_sysenter_eip, __readmsr(MSR_IA32_SYSENTER_EIP));
        __vmx_vmwrite(host_state_fields.natural_state.ia32_sysenter_esp, __readmsr(MSR_IA32_SYSENTER_ESP));

        //
        // left here just for test
        //
        __vmx_vmwrite(guest_state_fields.natural_state.rsp, g_VirtualGuestMemoryAddress); // setup guest sp
        __vmx_vmwrite(guest_state_fields.natural_state.rip, g_VirtualGuestMemoryAddress); // setup guest ip
        __vmx_vmwrite(host_state_fields.natural_state.rsp, GuestState->vmm_stack + VMM_STACK_SIZE - 1);
        __vmx_vmwrite(host_state_fields.natural_state.rip, AsmVmexitHandler);

        Status = TRUE;
Exit:
        return Status;
}

VOID
ResumeToNextInstruction()
{
        PVOID ResumeRIP = NULL;
        PVOID CurrentRIP = NULL;
        ULONG ExitInstructionLength = 0;

        __vmx_vmread(GUEST_RIP, &CurrentRIP);
        __vmx_vmread(VM_EXIT_INSTRUCTION_LEN, &ExitInstructionLength);

        ResumeRIP = (PCHAR)CurrentRIP + ExitInstructionLength;

        __vmx_vmwrite(GUEST_RIP, (ULONG64)ResumeRIP);
}

VOID
VmResumeInstruction()
{
        __vmx_vmresume();

        // if VMRESUME succeeds will never be here !

        ULONG64 ErrorCode = 0;
        __vmx_vmread(VM_INSTRUCTION_ERROR, &ErrorCode);
        __vmx_off();
        DbgPrint("[*] VMRESUME Error : 0x%llx\n", ErrorCode);

        //
        // It's such a bad error because we don't where to go!
        // prefer to break
        //
        DbgBreakPoint();
}

VOID
MainVmexitHandler(PGUEST_REGS GuestRegs)
{
        ULONG ExitReason = 0;
        __vmx_vmread(VM_EXIT_REASON, &ExitReason);

        ULONG ExitQualification = 0;
        __vmx_vmread(EXIT_QUALIFICATION, &ExitQualification);

        DbgPrint("\nVM_EXIT_REASION 0x%x\n", ExitReason & 0xffff);
        DbgPrint("\EXIT_QUALIFICATION 0x%x\n", ExitQualification);

        switch (ExitReason)
        {
                //
                // 25.1.2  Instructions That Cause VM Exits Unconditionally
                // The following instructions cause VM exits when they are executed in VMX non-root operation: CPUID, GETSEC,
                // INVD, and XSETBV. This is also true of instructions introduced with VMX, which include: INVEPT, INVVPID,
                // VMCALL, VMCLEAR, VMLAUNCH, VMPTRLD, VMPTRST, VMRESUME, VMXOFF, and VMXON.
                //

        case EXIT_REASON_VMCLEAR:
        case EXIT_REASON_VMPTRLD:
        case EXIT_REASON_VMPTRST:
        case EXIT_REASON_VMREAD:
        case EXIT_REASON_VMRESUME:
        case EXIT_REASON_VMWRITE:
        case EXIT_REASON_VMXOFF:
        case EXIT_REASON_VMXON:
        case EXIT_REASON_VMLAUNCH:
        {
                break;
        }
        case EXIT_REASON_HLT:
        {
                DbgPrint("[*] Execution of HLT detected... \n");

                //
                // that's enough for now ;)
                //
                __vmx_terminate();

                break;
        }
        case EXIT_REASON_EXCEPTION_NMI:
        {
                break;
        }

        case EXIT_REASON_CPUID:
        {
                break;
        }

        case EXIT_REASON_INVD:
        {
                break;
        }

        case EXIT_REASON_VMCALL:
        {
                break;
        }

        case EXIT_REASON_CR_ACCESS:
        {
                break;
        }

        case EXIT_REASON_MSR_READ:
        {
                break;
        }

        case EXIT_REASON_MSR_WRITE:
        {
                break;
        }

        case EXIT_REASON_EPT_VIOLATION:
        {
                break;
        }

        default:
        {
                // DbgBreakPoint();
                break;
        }
        }
}
//-----------------------------------------------------------------------------//
