#include "vmcs.h"

#include "ia32.h"
#include "vmx.h"
#include "encode.h"
#include "arch.h"
#include <intrin.h>

VMCS_GUEST_STATE_FIELDS   guest_state_fields   = {0};
VMCS_HOST_STATE_FIELDS    host_state_fields    = {0};
VMCS_CONTROL_STATE_FIELDS control_state_fields = {0};
VMCS_EXIT_STATE_FIELDS    exit_state_fields    = {0};

STATIC
UINT32
__segmentar(SEGMENT_SELECTOR* Selector)
{
        VMX_SEGMENT_ACCESS_RIGHTS ar = {0};

        /*
         * If the table is set to the GDT and there is no index, set the segment as unusable.
         */
        if (Selector->Table == FALSE && Selector->Index == FALSE)
        {
                ar.Unusable = TRUE;
                return ar.AsUInt;
        }

        /*
         * Use the lar instruction to load the access rights. remove the first byte as the value is
         * not used in the access rights. Set the unusable flag to false to allow the access rightse
         * to be used.
         */
        ar.AsUInt    = (__lar(Selector->AsUInt) >> 8);
        ar.Unusable  = 0;
        ar.Reserved1 = 0;
        ar.Reserved2 = 0;

        return ar.AsUInt;
}

STATIC
UINT32
AdjustMsrControl(_In_ UINT32 Control, _In_ UINT32 Msr)
{
        MSR msr     = {0};
        msr.Content = __readmsr(Msr);

        Control &= msr.High;
        Control |= msr.Low;

        return Control;
}

/*
 * Given either the LDT or GDT base, return the segment descriptor given the selector talble index.
 * We do this by taking the Selectors Index value and multiplying it by 8 as each entry is the size
 * of a pointer.
 */
STATIC
SEGMENT_DESCRIPTOR_64*
GetSegmentDescriptor(_In_ UINT64 TableBase, _In_ SEGMENT_SELECTOR* Selector)
{
        return (SEGMENT_DESCRIPTOR_64*)(TableBase + Selector->Index * 8);
}

STATIC
UINT64
GetSegmentDescriptorBase(_In_ SEGMENT_DESCRIPTOR_64* Descriptor)
{
        UINT64 base = Descriptor->BaseAddressHigh << 24 | Descriptor->BaseAddressMiddle << 16 |
                      Descriptor->BaseAddressLow;

        /*
         * If our our descriptor is a system descriptor and, more specifically, points to the TSS -
         * it means we need to expand the base to 16 bytes. The reason for this is as most
         * descriptors are 8 bytes, the call-gate, IDT and LDT/TSS descriptors are expanded to 16
         * bytes.
         */
        if (Descriptor->DescriptorType == SEGMENT_DESCRIPTOR_TYPE_SYSTEM &&
            (Descriptor->Type == SEGMENT_DESCRIPTOR_TYPE_TSS_AVAILABLE ||
             Descriptor->Type == SEGMENT_DESCRIPTOR_TYPE_TSS_BUSY))
                base |= (UINT64)(((SEGMENT_DESCRIPTOR_64*)Descriptor)->BaseAddressUpper) << 32;

        return base;
}

STATIC
UINT64
__segmentbase(_In_ SEGMENT_DESCRIPTOR_REGISTER_64* Gdtr, _In_ SEGMENT_SELECTOR* Selector)
{
        if (!Selector->AsUInt)
                return 0;

        SEGMENT_DESCRIPTOR_64* descriptor = GetSegmentDescriptor(Gdtr->BaseAddress, Selector);

        /*
         * Selector->Table specifies the descriptor table to use. Clearing the flag selects the GDT
         * while setting the flags selects the current LDT.
         *
         * Because all execution will happen within the context of the OS, we don't need to worry
         * about LDT descriptors
         */
        if (Selector->Table == TRUE)
                return 0;

        /*
         * Given our segment descriptor, find the base address the descriper describes and return
         * it.
         */
        return GetSegmentDescriptorBase(descriptor);
}

STATIC
VOID
VmcsWriteHostStateFields(_In_ PVIRTUAL_MACHINE_STATE GuestState)
{
        SEGMENT_DESCRIPTOR_REGISTER_64 gdtr = {0};
        __sgdt(&gdtr);


        SEGMENT_SELECTOR               tr   = {0};
        tr.AsUInt                           = __readtr();

        __vmx_vmwrite(host_state_fields.natural_state.tr_base, __segmentbase(&gdtr, &tr));

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

        __vmx_vmwrite(host_state_fields.natural_state.rsp,
                      GuestState->vmm_stack_va + VMM_STACK_SIZE - 1);
        __vmx_vmwrite(host_state_fields.natural_state.rip, VmexitHandler);

        __vmx_vmwrite(host_state_fields.natural_state.fs_base, __readmsr(MSR_FS_BASE));
        __vmx_vmwrite(host_state_fields.natural_state.gs_base, __readmsr(MSR_GS_BASE));

        __vmx_vmwrite(host_state_fields.dword_state.ia32_sysenter_cs,
                      __readmsr(MSR_IA32_SYSENTER_CS));
        __vmx_vmwrite(host_state_fields.natural_state.ia32_sysenter_eip,
                      __readmsr(MSR_IA32_SYSENTER_EIP));
        __vmx_vmwrite(host_state_fields.natural_state.ia32_sysenter_esp,
                      __readmsr(MSR_IA32_SYSENTER_ESP));
}

STATIC
VOID
VmcsWriteGuestStateFields(_In_ PVOID StackPointer, _In_ PVIRTUAL_MACHINE_STATE GuestState)
{
        SEGMENT_SELECTOR es   = {0};
        SEGMENT_SELECTOR cs   = {0};
        SEGMENT_SELECTOR ss   = {0};
        SEGMENT_SELECTOR ds   = {0};
        SEGMENT_SELECTOR fs   = {0};
        SEGMENT_SELECTOR gs   = {0};
        SEGMENT_SELECTOR tr   = {0};
        SEGMENT_SELECTOR ldtr = {0};

        es.AsUInt  = __reades();
        cs.AsUInt  = __readcs();
        ss.AsUInt  = __readss();
        ds.AsUInt  = __readds();
        fs.AsUInt  = __readfs();
        gs.AsUInt  = __readgs();
        tr.AsUInt  = __readtr();
        ldtr.Table = __readldtr();

        SEGMENT_DESCRIPTOR_REGISTER_64 gdtr = {0};
        SEGMENT_DESCRIPTOR_REGISTER_64 idtr = {0};

        __sgdt(&gdtr);
        __sidt(&idtr);

        __vmx_vmwrite(guest_state_fields.word_state.es_selector, es.AsUInt);
        __vmx_vmwrite(guest_state_fields.word_state.cs_selector, cs.AsUInt);
        __vmx_vmwrite(guest_state_fields.word_state.ss_selector, ss.AsUInt);
        __vmx_vmwrite(guest_state_fields.word_state.ds_selector, ds.AsUInt);
        __vmx_vmwrite(guest_state_fields.word_state.fs_selector, fs.AsUInt);
        __vmx_vmwrite(guest_state_fields.word_state.gs_selector, gs.AsUInt);
        __vmx_vmwrite(guest_state_fields.word_state.tr_selector, tr.AsUInt);
        __vmx_vmwrite(guest_state_fields.word_state.ldtr_selector, ldtr.AsUInt);

        __vmx_vmwrite(guest_state_fields.natural_state.es_base, __segmentbase(&gdtr, &es));
        __vmx_vmwrite(guest_state_fields.natural_state.cs_base, __segmentbase(&gdtr, &cs));
        __vmx_vmwrite(guest_state_fields.natural_state.ss_base, __segmentbase(&gdtr, &ss));
        __vmx_vmwrite(guest_state_fields.natural_state.ds_base, __segmentbase(&gdtr, &ds));
        __vmx_vmwrite(guest_state_fields.natural_state.fs_base, __segmentbase(&gdtr, &fs));
        __vmx_vmwrite(guest_state_fields.natural_state.gs_base, __segmentbase(&gdtr, &gs));
        __vmx_vmwrite(guest_state_fields.natural_state.tr_base, __segmentbase(&gdtr, &tr));
        __vmx_vmwrite(guest_state_fields.natural_state.ldtr_base, __segmentbase(&gdtr, &ldtr));

        __vmx_vmwrite(guest_state_fields.dword_state.es_limit, __segmentlimit(__reades()));
        __vmx_vmwrite(guest_state_fields.dword_state.cs_limit, __segmentlimit(__readcs()));
        __vmx_vmwrite(guest_state_fields.dword_state.ss_limit, __segmentlimit(__readss()));
        __vmx_vmwrite(guest_state_fields.dword_state.ds_limit, __segmentlimit(__readds()));
        __vmx_vmwrite(guest_state_fields.dword_state.fs_limit, __segmentlimit(__readfs()));
        __vmx_vmwrite(guest_state_fields.dword_state.gs_limit, __segmentlimit(__readgs()));
        __vmx_vmwrite(guest_state_fields.dword_state.tr_limit, __segmentlimit(__readtr()));
        __vmx_vmwrite(guest_state_fields.dword_state.ldtr_limit, __segmentlimit(__readldtr()));

        __vmx_vmwrite(guest_state_fields.dword_state.es_access_rights, __segmentar(&es));
        __vmx_vmwrite(guest_state_fields.dword_state.cs_access_rights, __segmentar(&cs));
        __vmx_vmwrite(guest_state_fields.dword_state.ss_access_rights, __segmentar(&ss));
        __vmx_vmwrite(guest_state_fields.dword_state.ds_access_rights, __segmentar(&ds));
        __vmx_vmwrite(guest_state_fields.dword_state.fs_access_rights, __segmentar(&fs));
        __vmx_vmwrite(guest_state_fields.dword_state.gs_access_rights, __segmentar(&gs));
        __vmx_vmwrite(guest_state_fields.dword_state.tr_access_rights, __segmentar(&tr));
        __vmx_vmwrite(guest_state_fields.dword_state.ldtr_access_rights, __segmentar(&ldtr));

        __vmx_vmwrite(guest_state_fields.dword_state.gdtr_limit, gdtr.Limit);
        __vmx_vmwrite(guest_state_fields.dword_state.idtr_limit, idtr.Limit);

        __vmx_vmwrite(guest_state_fields.natural_state.gdtr_base, gdtr.BaseAddress);
        __vmx_vmwrite(guest_state_fields.natural_state.idtr_base, idtr.BaseAddress);

        __vmx_vmwrite(guest_state_fields.qword_state.vmcs_link_pointer, ~0ull);

        /*
         * Simply set the cr0, cr3, cr4 and dr7 to what the guest was running with before.
         */
        __vmx_vmwrite(guest_state_fields.natural_state.cr0, __readcr0());
        __vmx_vmwrite(guest_state_fields.natural_state.cr3, __readcr3());
        __vmx_vmwrite(guest_state_fields.natural_state.cr4, __readcr4());
        __vmx_vmwrite(guest_state_fields.natural_state.dr7, 0x400);

        /*
         * fffff807`5347200b 0f03c8          lsl     ecx,eax
         *
         * the lsl instruction here causes a page fault on turning vmx back on after vmx is
         * initiated again after returning from sleep
         */

        __vmx_vmwrite(guest_state_fields.natural_state.rflags, __readrflags());

        __vmx_vmwrite(guest_state_fields.dword_state.sysenter_cs, __readmsr(MSR_IA32_SYSENTER_CS));
        __vmx_vmwrite(guest_state_fields.natural_state.sysenter_eip,
                      __readmsr(MSR_IA32_SYSENTER_EIP));
        __vmx_vmwrite(guest_state_fields.natural_state.sysenter_esp,
                      __readmsr(MSR_IA32_SYSENTER_ESP));
        __vmx_vmwrite(guest_state_fields.natural_state.fs_base, __readmsr(MSR_FS_BASE));
        __vmx_vmwrite(guest_state_fields.natural_state.gs_base, __readmsr(MSR_GS_BASE));

        /*
         * Since the goal of this hypervisor is to virtualise and already running operating system,
         * once we initiate VMX, we want to set the RIP and RSP set to the values they were before
         * the core was interrupted by our inter process interrupt. This means once vmx has been
         * initiated, guest operation will continue as normal as if nothing happened.
         */
        __vmx_vmwrite(guest_state_fields.natural_state.rsp, StackPointer);
        __vmx_vmwrite(guest_state_fields.natural_state.rip, VmxRestoreState);
}

STATIC
VOID
VmcsWriteControlStateFields(_In_ PVIRTUAL_MACHINE_STATE GuestState)
{
        /*
         * ActivateSecondaryControls activates the secondary processor-based
         * VM-execution controls. If UseMsrBitmaps is not set, all RDMSR and
         * WRMSR instructions cause vm-exits.
         */
        IA32_VMX_PROCBASED_CTLS_REGISTER proc_ctls = {0};
        proc_ctls.ActivateSecondaryControls        = TRUE;
        proc_ctls.UseMsrBitmaps                    = TRUE;
        proc_ctls.Cr3LoadExiting                   = TRUE;
        proc_ctls.Cr3StoreExiting                  = TRUE;

        __vmx_vmwrite(control_state_fields.dword_state.processor_based_vm_execution_controls,
                      AdjustMsrControl((UINT32)proc_ctls.AsUInt, MSR_IA32_VMX_PROCBASED_CTLS));

        /*
         * Ensure RDTSCP, INVPCID and XSAVES/XRSTORS do not raise an invalid
         * opcode exception.
         */
        IA32_VMX_PROCBASED_CTLS2_REGISTER proc_ctls2 = {0};
        proc_ctls2.EnableRdtscp                      = TRUE;
        proc_ctls2.EnableInvpcid                     = TRUE;
        proc_ctls2.EnableXsaves                      = TRUE;

        __vmx_vmwrite(
            control_state_fields.dword_state.secondary_processor_based_vm_execution_controls,
            AdjustMsrControl((UINT32)proc_ctls2.AsUInt, MSR_IA32_VMX_PROCBASED_CTLS2));

        /*
         * Lets not force a vmexit on any external interrupts
         */
        IA32_VMX_PINBASED_CTLS_REGISTER pin_ctls = {0};
        pin_ctls.NmiExiting                      = FALSE;

        __vmx_vmwrite(control_state_fields.dword_state.pin_based_vm_execution_controls,
                      AdjustMsrControl((UINT32)pin_ctls.AsUInt, MSR_IA32_VMX_PINBASED_CTLS));

        /*
         * Set all 32 bits to ensure every exception is caught
         */
        __vmx_vmwrite(control_state_fields.dword_state.exception_bitmap, 0ul);

        /*
         * Ensure we acknowledge interrupts on VMEXIT and are in 64 bit mode.
         */
        IA32_VMX_EXIT_CTLS_REGISTER exit_ctls = {0};
        exit_ctls.AcknowledgeInterruptOnExit  = TRUE;
        exit_ctls.HostAddressSpaceSize        = TRUE;

        __vmx_vmwrite(control_state_fields.dword_state.vmexit_controls,
                      AdjustMsrControl((UINT32)exit_ctls.AsUInt, MSR_IA32_VMX_EXIT_CTLS));

        /*
         * Ensure we are in 64bit mode on VMX entry.
         */
        IA32_VMX_ENTRY_CTLS_REGISTER entry_ctls = {0};
        entry_ctls.Ia32EModeGuest               = TRUE;

        __vmx_vmwrite(control_state_fields.dword_state.vmentry_controls,
                      AdjustMsrControl((UINT32)entry_ctls.AsUInt, MSR_IA32_VMX_ENTRY_CTLS));

        __vmx_vmwrite(control_state_fields.qword_state.msr_bitmap_address,
                      GuestState->msr_bitmap_pa);
}

NTSTATUS
SetupVmcs(_In_ PVIRTUAL_MACHINE_STATE GuestState, _In_ PVOID StackPointer)
{
        EncodeVmcsControlStateFields(&control_state_fields);
        EncodeVmcsGuestStateFields(&guest_state_fields);
        EncodeVmcsHostStateFields(&host_state_fields);
        EncodeVmcsExitStateFields(&exit_state_fields);

        if (__vmx_vmclear(&GuestState->vmcs_region_pa) != VMX_OK)
        {
                DEBUG_ERROR("Unable to clear the vmcs region");
                return STATUS_UNSUCCESSFUL;
        }

        if (__vmx_vmptrld(&GuestState->vmcs_region_pa) != VMX_OK)
        {
                DEBUG_ERROR("vmptrld failed with status: %lx", VmcsReadInstructionErrorCode());
                return STATUS_UNSUCCESSFUL;
        }

        VmcsWriteControlStateFields(GuestState);
        VmcsWriteGuestStateFields(StackPointer, GuestState);
        VmcsWriteHostStateFields(GuestState);

        return STATUS_SUCCESS;
}

UINT32
VmcsReadInstructionErrorCode()
{
        UINT32 code = 0;
        __vmx_vmread(exit_state_fields.dword_state.instruction_error, &code);
        return code;
}

UINT32
VmcsReadInstructionLength()
{
        UINT32 length = 0;
        __vmx_vmread(exit_state_fields.dword_state.instruction_length, &length);
        return length;
}

UINT64
VmcsReadGuestRip()
{
        UINT64 rip = 0;
        __vmx_vmread(guest_state_fields.natural_state.rip, &rip);
        return rip;
}

UINT32
VmcsReadExitReason()
{
        UINT32 reason = 0;
        __vmx_vmread(exit_state_fields.dword_state.reason, &reason);
        return reason;
}

VOID
VmcsWriteGuestRip(_In_ UINT64 NewValue)
{
        __vmx_vmwrite(guest_state_fields.natural_state.rip, NewValue);
}

VOID
VmcsWriteGuestCr0(_In_ UINT64 NewValue)
{
        __vmx_vmwrite(guest_state_fields.natural_state.cr0, NewValue);
}

VOID
VmcsWriteGuestCr0ReadShadow(_In_ UINT64 NewValue)
{
        __vmx_vmwrite(control_state_fields.natural_state.cr0_read_shadow, NewValue);
}

VOID
VmcsWriteGuestCr3(_In_ UINT64 NewValue)
{
        __vmx_vmwrite(guest_state_fields.natural_state.cr3, NewValue);
}

VOID
VmcsWriteGuestCr4(_In_ UINT64 NewValue)
{
        __vmx_vmwrite(guest_state_fields.natural_state.cr4, NewValue);
}

VOID
VmcsWriteGuestCr4ReadShadow(_In_ UINT64 NewValue)
{
        __vmx_vmwrite(control_state_fields.natural_state.cr4_read_shadow, NewValue);
}

UINT64
VmcsReadGuestRsp()
{
        UINT64 rsp = 0;
        __vmx_vmread(guest_state_fields.natural_state.rsp, &rsp);
        return rsp;
}

UINT32
VmcsReadExitQualification()
{
        UINT32 exit_qualification = 0;
        __vmx_vmread(exit_state_fields.natural_state.exit_qualification, &exit_qualification);
        return exit_qualification;
}

UINT64
VmcsReadGuestCr0()
{
        UINT64 cr0 = 0;
        __vmx_vmread(guest_state_fields.natural_state.cr0, &cr0);
        return cr0;
}

UINT64
VmcsReadGuestCr3()
{
        UINT64 cr3 = 0;
        __vmx_vmread(guest_state_fields.natural_state.cr3, &cr3);
        return cr3;
}

UINT64
VmcsReadGuestCr4()
{
        UINT64 cr4 = 0;
        __vmx_vmread(guest_state_fields.natural_state.cr4, &cr4);
        return cr4;
}

UINT64
VmmReadGuestRip()
{
        return vmm_state[KeGetCurrentProcessorNumber()].exit_state.guest_rip;
}

UINT64
VmmReadGuestRsp()
{
        return vmm_state[KeGetCurrentProcessorNumber()].exit_state.guest_rsp;
}

UINT64
VmcsReadGuestFsBase()
{
        UINT64 base = 0;
        __vmx_vmread(guest_state_fields.natural_state.fs_base, &base);
        return base;
}

UINT64
VmcsReadGuestGsBase()
{
        UINT64 base = 0;
        __vmx_vmread(guest_state_fields.natural_state.gs_base, &base);
        return base;
}

UINT64
VmcsReadGuestGdtrBase()
{
        UINT64 base = 0;
        __vmx_vmread(guest_state_fields.natural_state.gdtr_base, &base);
        return base;
}

UINT32
VmcsReadGuestGdtrLimit()
{
        UINT32 limit = 0;
        __vmx_vmread(guest_state_fields.dword_state.gdtr_limit, &limit);
        return limit;
}

UINT64
VmcsReadGuestIdtrBase()
{
        UINT64 base = 0;
        __vmx_vmread(guest_state_fields.natural_state.idtr_base, &base);
        return base;
}

UINT32
VmcsReadGuestIdtrLimit()
{
        UINT32 limit = 0;
        __vmx_vmread(guest_state_fields.dword_state.idtr_limit, &limit);
        return limit;
}

UINT32
VmcsReadExitInterruptionInfo()
{
        UINT32 info = 0;
        __vmx_vmread(exit_state_fields.dword_state.interruption_info, &info);
        return info;
}

UINT32
VmcsWriteEntryInterruptionInfo(_In_ UINT32 Value)
{
        __vmx_vmwrite(control_state_fields.dword_state.vmentry_interruption_info, Value);
}

UINT32
VmcsWriteEntryInstructionLength(_In_ UINT32 Value)
{
        __vmx_vmwrite(control_state_fields.dword_state.vmentry_instruction_length, Value);
}