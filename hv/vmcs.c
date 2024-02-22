#include "vmcs.h"

#include "ia32.h"
#include "vmx.h"
#include "arch.h"
#include <intrin.h>

STATIC
UINT32
__segmentar(SEGMENT_SELECTOR* Selector)
{
        VMX_SEGMENT_ACCESS_RIGHTS ar = {0};

        /*
         * If the table is set to the GDT and there is no index, set the segment as unusable.
         */
        if (Selector->Table == FALSE && Selector->Index == FALSE) {
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
        SEGMENT_DESCRIPTOR_REGISTER_64 idtr = {0};

        __sgdt(&gdtr);
        __sidt(&idtr);

        SEGMENT_SELECTOR tr = {0};

        tr.AsUInt = __readtr();

        __vmx_vmwrite(VMCS_HOST_ES_SELECTOR, __reades() & VMCS_HOST_SELECTOR_MASK);
        __vmx_vmwrite(VMCS_HOST_CS_SELECTOR, __readcs() & VMCS_HOST_SELECTOR_MASK);
        __vmx_vmwrite(VMCS_HOST_SS_SELECTOR, __readss() & VMCS_HOST_SELECTOR_MASK);
        __vmx_vmwrite(VMCS_HOST_DS_SELECTOR, __readds() & VMCS_HOST_SELECTOR_MASK);
        __vmx_vmwrite(VMCS_HOST_FS_SELECTOR, __readfs() & VMCS_HOST_SELECTOR_MASK);
        __vmx_vmwrite(VMCS_HOST_GS_SELECTOR, __readgs() & VMCS_HOST_SELECTOR_MASK);
        __vmx_vmwrite(VMCS_HOST_TR_SELECTOR, __readtr() & VMCS_HOST_SELECTOR_MASK);

        __vmx_vmwrite(VMCS_HOST_CR0, __readcr0());
        __vmx_vmwrite(VMCS_HOST_CR3, __readcr3());
        __vmx_vmwrite(VMCS_HOST_CR4, __readcr4());

        __vmx_vmwrite(VMCS_HOST_GDTR_BASE, gdtr.BaseAddress);
        __vmx_vmwrite(VMCS_HOST_IDTR_BASE, idtr.BaseAddress);

        __vmx_vmwrite(VMCS_HOST_RSP, GuestState->vmm_stack_va + VMX_HOST_STACK_SIZE - 1);
        __vmx_vmwrite(VMCS_HOST_RIP, VmexitHandler);

        __vmx_vmwrite(VMCS_HOST_FS_BASE, __readmsr(IA32_FS_BASE));
        __vmx_vmwrite(VMCS_HOST_GS_BASE, __readmsr(IA32_GS_BASE));
        __vmx_vmwrite(VMCS_HOST_TR_BASE, __segmentbase(&gdtr, &tr));

        __vmx_vmwrite(VMCS_HOST_SYSENTER_CS, __readmsr(IA32_SYSENTER_CS));
        __vmx_vmwrite(VMCS_HOST_SYSENTER_EIP, __readmsr(IA32_SYSENTER_EIP));
        __vmx_vmwrite(VMCS_HOST_SYSENTER_ESP, __readmsr(IA32_SYSENTER_ESP));
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

        __vmx_vmwrite(VMCS_GUEST_ES_SELECTOR, es.AsUInt);
        __vmx_vmwrite(VMCS_GUEST_CS_SELECTOR, cs.AsUInt);
        __vmx_vmwrite(VMCS_GUEST_SS_SELECTOR, ss.AsUInt);
        __vmx_vmwrite(VMCS_GUEST_DS_SELECTOR, ds.AsUInt);
        __vmx_vmwrite(VMCS_GUEST_FS_SELECTOR, fs.AsUInt);
        __vmx_vmwrite(VMCS_GUEST_GS_SELECTOR, gs.AsUInt);
        __vmx_vmwrite(VMCS_GUEST_TR_SELECTOR, tr.AsUInt);
        __vmx_vmwrite(VMCS_GUEST_LDTR_SELECTOR, ldtr.AsUInt);

        __vmx_vmwrite(VMCS_GUEST_ES_BASE, __segmentbase(&gdtr, &es));
        __vmx_vmwrite(VMCS_GUEST_CS_BASE, __segmentbase(&gdtr, &cs));
        __vmx_vmwrite(VMCS_GUEST_SS_BASE, __segmentbase(&gdtr, &ss));
        __vmx_vmwrite(VMCS_GUEST_DS_BASE, __segmentbase(&gdtr, &ds));
        __vmx_vmwrite(VMCS_GUEST_FS_BASE, __segmentbase(&gdtr, &fs));
        __vmx_vmwrite(VMCS_GUEST_GS_BASE, __segmentbase(&gdtr, &gs));
        __vmx_vmwrite(VMCS_GUEST_TR_BASE, __segmentbase(&gdtr, &tr));
        __vmx_vmwrite(VMCS_GUEST_LDTR_BASE, __segmentbase(&gdtr, &ldtr));

        __vmx_vmwrite(VMCS_GUEST_ES_LIMIT, __segmentlimit(__reades()));
        __vmx_vmwrite(VMCS_GUEST_CS_LIMIT, __segmentlimit(__readcs()));
        __vmx_vmwrite(VMCS_GUEST_SS_LIMIT, __segmentlimit(__readss()));
        __vmx_vmwrite(VMCS_GUEST_DS_LIMIT, __segmentlimit(__readds()));
        __vmx_vmwrite(VMCS_GUEST_FS_LIMIT, __segmentlimit(__readfs()));
        __vmx_vmwrite(VMCS_GUEST_GS_LIMIT, __segmentlimit(__readgs()));
        __vmx_vmwrite(VMCS_GUEST_TR_LIMIT, __segmentlimit(__readtr()));
        __vmx_vmwrite(VMCS_GUEST_LDTR_LIMIT, __segmentlimit(__readldtr()));

        __vmx_vmwrite(VMCS_GUEST_ES_ACCESS_RIGHTS, __segmentar(&es));
        __vmx_vmwrite(VMCS_GUEST_CS_ACCESS_RIGHTS, __segmentar(&cs));
        __vmx_vmwrite(VMCS_GUEST_SS_ACCESS_RIGHTS, __segmentar(&ss));
        __vmx_vmwrite(VMCS_GUEST_DS_ACCESS_RIGHTS, __segmentar(&ds));
        __vmx_vmwrite(VMCS_GUEST_FS_ACCESS_RIGHTS, __segmentar(&fs));
        __vmx_vmwrite(VMCS_GUEST_GS_ACCESS_RIGHTS, __segmentar(&gs));
        __vmx_vmwrite(VMCS_GUEST_TR_ACCESS_RIGHTS, __segmentar(&tr));
        __vmx_vmwrite(VMCS_GUEST_LDTR_ACCESS_RIGHTS, __segmentar(&ldtr));

        __vmx_vmwrite(VMCS_GUEST_GDTR_LIMIT, gdtr.Limit);
        __vmx_vmwrite(VMCS_GUEST_IDTR_LIMIT, idtr.Limit);
        __vmx_vmwrite(VMCS_GUEST_GDTR_BASE, gdtr.BaseAddress);
        __vmx_vmwrite(VMCS_GUEST_IDTR_BASE, idtr.BaseAddress);

        __vmx_vmwrite(VMCS_GUEST_VMCS_LINK_POINTER, ~0ull);

        __vmx_vmwrite(VMCS_GUEST_CR0, __readcr0());
        __vmx_vmwrite(VMCS_GUEST_CR3, __readcr3());
        __vmx_vmwrite(VMCS_GUEST_CR4, __readcr4());

        /*
         * fffff807`5347200b 0f03c8          lsl     ecx,eax
         *
         * the lsl instruction here causes a page fault on turning vmx back on after vmx is
         * initiated again after returning from sleep
         */

        __vmx_vmwrite(VMCS_GUEST_RFLAGS, __readrflags());
        __vmx_vmwrite(VMCS_GUEST_SYSENTER_CS, __readmsr(IA32_SYSENTER_CS));
        __vmx_vmwrite(VMCS_GUEST_SYSENTER_EIP, __readmsr(IA32_SYSENTER_EIP));
        __vmx_vmwrite(VMCS_GUEST_SYSENTER_ESP, __readmsr(IA32_SYSENTER_ESP));
        __vmx_vmwrite(VMCS_GUEST_FS_BASE, __readmsr(IA32_FS_BASE));
        __vmx_vmwrite(VMCS_GUEST_GS_BASE, __readmsr(IA32_GS_BASE));

        /*
         * Since the goal of this hypervisor is to virtualise and already running operating system,
         * once we initiate VMX, we want to set the RIP and RSP set to the values they were before
         * the core was interrupted by our inter process interrupt. This means once vmx has been
         * initiated, guest operation will continue as normal as if nothing happened.
         */
        __vmx_vmwrite(VMCS_GUEST_RSP, StackPointer);
        __vmx_vmwrite(VMCS_GUEST_RIP, VmxRestoreState);
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

        VmxVmWrite(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS,
                   AdjustMsrControl((UINT32)proc_ctls.AsUInt, IA32_VMX_PROCBASED_CTLS));

        /*
         * Ensure RDTSCP, INVPCID and XSAVES/XRSTORS do not raise an invalid
         * opcode exception.
         */
        IA32_VMX_PROCBASED_CTLS2_REGISTER proc_ctls2 = {0};
        proc_ctls2.EnableRdtscp                      = TRUE;
        proc_ctls2.EnableInvpcid                     = TRUE;
        proc_ctls2.EnableXsaves                      = TRUE;

        VmxVmWrite(VMCS_CTRL_SECONDARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS,
                   AdjustMsrControl((UINT32)proc_ctls2.AsUInt, IA32_VMX_PROCBASED_CTLS2));

        /*
         * Lets not force a vmexit on any external interrupts
         */
        IA32_VMX_PINBASED_CTLS_REGISTER pin_ctls = {0};
        pin_ctls.NmiExiting                      = FALSE;

        VmxVmWrite(VMCS_CTRL_PIN_BASED_VM_EXECUTION_CONTROLS,
                   AdjustMsrControl((UINT32)pin_ctls.AsUInt, IA32_VMX_PINBASED_CTLS));

        /*
         * Set all 32 bits to ensure every exception is caught
         */
        __vmx_vmwrite(VMCS_CTRL_EXCEPTION_BITMAP, 0ul);

        /*
         * Ensure we acknowledge interrupts on VMEXIT and are in 64 bit mode.
         */
        IA32_VMX_EXIT_CTLS_REGISTER exit_ctls = {0};
        exit_ctls.AcknowledgeInterruptOnExit  = TRUE;
        exit_ctls.HostAddressSpaceSize        = TRUE;

        __vmx_vmwrite(VMCS_CTRL_PRIMARY_VMEXIT_CONTROLS,
                      AdjustMsrControl((UINT32)exit_ctls.AsUInt, IA32_VMX_EXIT_CTLS));
        /*
         * Ensure we are in 64bit mode on VMX entry.
         */
        IA32_VMX_ENTRY_CTLS_REGISTER entry_ctls = {0};
        entry_ctls.Ia32EModeGuest               = TRUE;

        __vmx_vmwrite(VMCS_CTRL_VMENTRY_CONTROLS,
                      AdjustMsrControl((UINT32)entry_ctls.AsUInt, IA32_VMX_ENTRY_CTLS));

        __vmx_vmwrite(VMCS_CTRL_MSR_BITMAP_ADDRESS, GuestState->msr_bitmap_pa);
}

NTSTATUS
SetupVmcs(_In_ PVIRTUAL_MACHINE_STATE GuestState, _In_ PVOID StackPointer)
{
        UCHAR status = 0;

        status = __vmx_vmclear(&GuestState->vmcs_region_pa);

        if (!VMX_OK(status)) {
                DEBUG_ERROR("__vmx_vmclear failed with status %x", status);
                return STATUS_UNSUCCESSFUL;
        }

        status = __vmx_vmptrld(&GuestState->vmcs_region_pa);

        if (!VMX_OK(status)) {
                if (status == VMX_STATUS_OPERATION_FAILED)
                {
                        DEBUG_ERROR("__vmx_vmptrld failed with status: %llx",
                                    VmxVmRead(VMCS_VM_INSTRUCTION_ERROR));
                        return STATUS_UNSUCCESSFUL;
                }
                else
                {
                        DEBUG_ERROR("__vmx_vmptrld failed with no status.");
                        return STATUS_UNSUCCESSFUL;
                }
        }

        VmcsWriteControlStateFields(GuestState);
        VmcsWriteGuestStateFields(StackPointer, GuestState);
        VmcsWriteHostStateFields(GuestState);

        return STATUS_SUCCESS;
}

/* Wrapper functions to read and write to and from the vmcs. */
UINT64
VmxVmRead(_In_ UINT64 VmcsField)
{
        UINT64 result = 0;
        __vmx_vmread(VmcsField, &result);
        return result;
}

VOID
VmxVmWrite(_In_ UINT64 VmcsField, _In_ UINT64 Value)
{
        __vmx_vmwrite(VmcsField, Value);
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