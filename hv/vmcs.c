#include "vmcs.h"

#include "ia32.h"
#include "vmx.h"
#include "arch.h"
#include "log.h"

#include <intrin.h>

/* Wrapper functions to read and write to and from the vmcs. */
UINT64
HvVmcsRead(_In_ UINT64 VmcsField)
{
    UINT64 result = 0;
    __vmx_vmread(VmcsField, &result);
    return result;
}

VOID
HvVmcsWrite64(_In_ UINT64 VmcsField, _In_ UINT64 Value)
{
    __vmx_vmwrite(VmcsField, Value);
}

VOID
HvVmcsWrite32(_In_ UINT64 VmcsField, _In_ UINT32 Value)
{
    __vmx_vmwrite(VmcsField, Value);
}

/*
 * CS or SS segment selector contain the current protection level (CPL) for the
 * currently executing program.
 */
UINT16
HvVmcsGuestGetProtectionLevel()
{
    SEGMENT_SELECTOR cs = {
        .AsUInt = (UINT16)HvVmcsRead(VMCS_GUEST_CS_SELECTOR)};
    return cs.RequestPrivilegeLevel;
}

STATIC
UINT32
__segmentar(SEGMENT_SELECTOR* Selector)
{
    VMX_SEGMENT_ACCESS_RIGHTS ar = {0};

    /*
     * If the table is set to the GDT and there is no index, set the segment
     * as unusable.
     */
    if (Selector->Table == FALSE && Selector->Index == FALSE) {
        ar.Unusable = TRUE;
        return ar.AsUInt;
    }

    /*
     * Use the lar instruction to load the access rights. remove the first
     * byte as the value is not used in the access rights. Set the unusable
     * flag to false to allow the access rightse to be used.
     */
    ar.AsUInt = (__lar(Selector->AsUInt) >> 8);
    ar.Unusable = 0;
    ar.Reserved1 = 0;
    ar.Reserved2 = 0;

    return ar.AsUInt;
}

STATIC
UINT32
HvVmcsMsrAdjustControl(_In_ UINT32 Control, _In_ UINT32 Msr)
{
    ULARGE_INTEGER msr = {0};
    msr.QuadPart = __readmsr(Msr);

    Control &= msr.HighPart;
    Control |= msr.LowPart;

    return Control;
}

/*
 * Given either the LDT or GDT base, return the segment descriptor given the
 * selector talble index. We do this by taking the Selectors Index value and
 * multiplying it by 8 as each entry is the size of a pointer.
 */
STATIC
SEGMENT_DESCRIPTOR_64*
HvVmcsSegmentDescriptorGet(
    _In_ UINT64 TableBase,
    _In_ SEGMENT_SELECTOR* Selector)
{
    return (SEGMENT_DESCRIPTOR_64*)(TableBase +
                                    Selector->Index * sizeof(UINT64));
}

STATIC
UINT64
HvVmcsSegmentDescriptorGetBase(_In_ SEGMENT_DESCRIPTOR_64* Descriptor)
{
    UINT64 base = Descriptor->BaseAddressHigh << 24 |
                  Descriptor->BaseAddressMiddle << 16 |
                  Descriptor->BaseAddressLow;

    /*
     * If our our descriptor is a system descriptor and, more specifically,
     * points to the TSS - it means we need to expand the base to 16 bytes.
     * The reason for this is as most descriptors are 8 bytes, the
     * call-gate, IDT and LDT/TSS descriptors are expanded to 16 bytes.
     */
    if (Descriptor->DescriptorType == SEGMENT_DESCRIPTOR_TYPE_SYSTEM &&
        (Descriptor->Type == SEGMENT_DESCRIPTOR_TYPE_TSS_AVAILABLE ||
         Descriptor->Type == SEGMENT_DESCRIPTOR_TYPE_TSS_BUSY))
        base |= (UINT64)(((SEGMENT_DESCRIPTOR_64*)Descriptor)->BaseAddressUpper)
                << 32;

    return base;
}

STATIC
UINT64
__segmentbase(
    _In_ SEGMENT_DESCRIPTOR_REGISTER_64* Gdtr,
    _In_ SEGMENT_SELECTOR* Selector)
{
    if (!Selector->AsUInt)
        return 0;

    SEGMENT_DESCRIPTOR_64* descriptor =
        HvVmcsSegmentDescriptorGet(Gdtr->BaseAddress, Selector);

    /*
     * Selector->Table specifies the descriptor table to use. Clearing the
     * flag selects the GDT while setting the flags selects the current LDT.
     *
     * Because all execution will happen within the context of the OS, we
     * don't need to worry about LDT descriptors
     */
    if (Selector->Table == TRUE)
        return 0;

    /*
     * Given our segment descriptor, find the base address the descriper
     * describes and return it.
     */
    return HvVmcsSegmentDescriptorGetBase(descriptor);
}

STATIC
VOID
HvVmcsHostStateFieldsWrite(_In_ PVCPU GuestState)
{
    SEGMENT_DESCRIPTOR_REGISTER_64 gdtr = {0};
    SEGMENT_DESCRIPTOR_REGISTER_64 idtr = {0};

    __sgdt(&gdtr);
    __sidt(&idtr);

    SEGMENT_SELECTOR tr = {0};

    tr.AsUInt = __readtr();

    HvVmcsWrite64(VMCS_HOST_ES_SELECTOR, __reades() & VMCS_HOST_SELECTOR_MASK);
    HvVmcsWrite64(VMCS_HOST_CS_SELECTOR, __readcs() & VMCS_HOST_SELECTOR_MASK);
    HvVmcsWrite64(VMCS_HOST_SS_SELECTOR, __readss() & VMCS_HOST_SELECTOR_MASK);
    HvVmcsWrite64(VMCS_HOST_DS_SELECTOR, __readds() & VMCS_HOST_SELECTOR_MASK);
    HvVmcsWrite64(VMCS_HOST_FS_SELECTOR, __readfs() & VMCS_HOST_SELECTOR_MASK);
    HvVmcsWrite64(VMCS_HOST_GS_SELECTOR, __readgs() & VMCS_HOST_SELECTOR_MASK);
    HvVmcsWrite64(VMCS_HOST_TR_SELECTOR, __readtr() & VMCS_HOST_SELECTOR_MASK);

    HvVmcsWrite64(VMCS_HOST_CR0, __readcr0());
    HvVmcsWrite64(VMCS_HOST_CR3, __readcr3());
    HvVmcsWrite64(VMCS_HOST_CR4, __readcr4());

    HvVmcsWrite64(VMCS_HOST_GDTR_BASE, gdtr.BaseAddress);
    HvVmcsWrite64(VMCS_HOST_IDTR_BASE, idtr.BaseAddress);

    HvVmcsWrite64(
        VMCS_HOST_RSP,
        GuestState->vmm_stack_va + VMX_HOST_STACK_SIZE);
    HvVmcsWrite64(VMCS_HOST_RIP, HvArchVmExitHandler);

    HvVmcsWrite64(VMCS_HOST_FS_BASE, __readmsr(IA32_FS_BASE));
    HvVmcsWrite64(VMCS_HOST_GS_BASE, __readmsr(IA32_GS_BASE));
    HvVmcsWrite64(VMCS_HOST_TR_BASE, __segmentbase(&gdtr, &tr));

    HvVmcsWrite64(VMCS_HOST_SYSENTER_CS, __readmsr(IA32_SYSENTER_CS));
    HvVmcsWrite64(VMCS_HOST_SYSENTER_EIP, __readmsr(IA32_SYSENTER_EIP));
    HvVmcsWrite64(VMCS_HOST_SYSENTER_ESP, __readmsr(IA32_SYSENTER_ESP));
}

STATIC
VOID
HvVmcsGuestStateFieldsWrite(_In_ PVOID StackPointer, _In_ PVCPU GuestState)
{
    SEGMENT_SELECTOR es = {0};
    SEGMENT_SELECTOR cs = {0};
    SEGMENT_SELECTOR ss = {0};
    SEGMENT_SELECTOR ds = {0};
    SEGMENT_SELECTOR fs = {0};
    SEGMENT_SELECTOR gs = {0};
    SEGMENT_SELECTOR tr = {0};
    SEGMENT_SELECTOR ldtr = {0};

    es.AsUInt = __reades();
    cs.AsUInt = __readcs();
    ss.AsUInt = __readss();
    ds.AsUInt = __readds();
    fs.AsUInt = __readfs();
    gs.AsUInt = __readgs();
    tr.AsUInt = __readtr();
    ldtr.Table = __readldtr();

    SEGMENT_DESCRIPTOR_REGISTER_64 gdtr = {0};
    SEGMENT_DESCRIPTOR_REGISTER_64 idtr = {0};

    __sgdt(&gdtr);
    __sidt(&idtr);

    HvVmcsWrite64(VMCS_GUEST_ES_SELECTOR, es.AsUInt);
    HvVmcsWrite64(VMCS_GUEST_CS_SELECTOR, cs.AsUInt);
    HvVmcsWrite64(VMCS_GUEST_SS_SELECTOR, ss.AsUInt);
    HvVmcsWrite64(VMCS_GUEST_DS_SELECTOR, ds.AsUInt);
    HvVmcsWrite64(VMCS_GUEST_FS_SELECTOR, fs.AsUInt);
    HvVmcsWrite64(VMCS_GUEST_GS_SELECTOR, gs.AsUInt);
    HvVmcsWrite64(VMCS_GUEST_TR_SELECTOR, tr.AsUInt);
    HvVmcsWrite64(VMCS_GUEST_LDTR_SELECTOR, ldtr.AsUInt);

    HvVmcsWrite64(VMCS_GUEST_ES_BASE, __segmentbase(&gdtr, &es));
    HvVmcsWrite64(VMCS_GUEST_CS_BASE, __segmentbase(&gdtr, &cs));
    HvVmcsWrite64(VMCS_GUEST_SS_BASE, __segmentbase(&gdtr, &ss));
    HvVmcsWrite64(VMCS_GUEST_DS_BASE, __segmentbase(&gdtr, &ds));
    HvVmcsWrite64(VMCS_GUEST_FS_BASE, __segmentbase(&gdtr, &fs));
    HvVmcsWrite64(VMCS_GUEST_GS_BASE, __segmentbase(&gdtr, &gs));
    HvVmcsWrite64(VMCS_GUEST_TR_BASE, __segmentbase(&gdtr, &tr));
    HvVmcsWrite64(VMCS_GUEST_LDTR_BASE, __segmentbase(&gdtr, &ldtr));

    HvVmcsWrite64(VMCS_GUEST_ES_LIMIT, __segmentlimit(es.AsUInt));
    HvVmcsWrite64(VMCS_GUEST_CS_LIMIT, __segmentlimit(cs.AsUInt));
    HvVmcsWrite64(VMCS_GUEST_SS_LIMIT, __segmentlimit(ss.AsUInt));
    HvVmcsWrite64(VMCS_GUEST_DS_LIMIT, __segmentlimit(ds.AsUInt));
    HvVmcsWrite64(VMCS_GUEST_FS_LIMIT, __segmentlimit(fs.AsUInt));
    HvVmcsWrite64(VMCS_GUEST_GS_LIMIT, __segmentlimit(gs.AsUInt));
    HvVmcsWrite64(VMCS_GUEST_TR_LIMIT, __segmentlimit(tr.AsUInt));
    HvVmcsWrite64(VMCS_GUEST_LDTR_LIMIT, __segmentlimit(ldtr.AsUInt));

    HvVmcsWrite64(VMCS_GUEST_ES_ACCESS_RIGHTS, __segmentar(&es));
    HvVmcsWrite64(VMCS_GUEST_CS_ACCESS_RIGHTS, __segmentar(&cs));
    HvVmcsWrite64(VMCS_GUEST_SS_ACCESS_RIGHTS, __segmentar(&ss));
    HvVmcsWrite64(VMCS_GUEST_DS_ACCESS_RIGHTS, __segmentar(&ds));
    HvVmcsWrite64(VMCS_GUEST_FS_ACCESS_RIGHTS, __segmentar(&fs));
    HvVmcsWrite64(VMCS_GUEST_GS_ACCESS_RIGHTS, __segmentar(&gs));
    HvVmcsWrite64(VMCS_GUEST_TR_ACCESS_RIGHTS, __segmentar(&tr));
    HvVmcsWrite64(VMCS_GUEST_LDTR_ACCESS_RIGHTS, __segmentar(&ldtr));

    HvVmcsWrite64(VMCS_GUEST_GDTR_LIMIT, gdtr.Limit);
    HvVmcsWrite64(VMCS_GUEST_IDTR_LIMIT, idtr.Limit);
    HvVmcsWrite64(VMCS_GUEST_GDTR_BASE, gdtr.BaseAddress);
    HvVmcsWrite64(VMCS_GUEST_IDTR_BASE, idtr.BaseAddress);

    HvVmcsWrite64(VMCS_GUEST_VMCS_LINK_POINTER, MAXULONG_PTR);

    HvVmcsWrite64(VMCS_GUEST_CR0, __readcr0());
    HvVmcsWrite64(VMCS_GUEST_CR3, __readcr3());
    HvVmcsWrite64(VMCS_GUEST_CR4, __readcr4());

    HvVmcsWrite64(VMCS_GUEST_RFLAGS, __readeflags());
    HvVmcsWrite64(VMCS_GUEST_SYSENTER_CS, __readmsr(IA32_SYSENTER_CS));
    HvVmcsWrite64(VMCS_GUEST_SYSENTER_EIP, __readmsr(IA32_SYSENTER_EIP));
    HvVmcsWrite64(VMCS_GUEST_SYSENTER_ESP, __readmsr(IA32_SYSENTER_ESP));
    HvVmcsWrite64(VMCS_GUEST_FS_BASE, __readmsr(IA32_FS_BASE));
    HvVmcsWrite64(VMCS_GUEST_GS_BASE, __readmsr(IA32_GS_BASE));

#if DEBUG
    HvVmcsWrite32(
        VMCS_GUEST_VMX_PREEMPTION_TIMER_VALUE,
        HvVmxGetVcpu()->preemption_time);
#endif

    /*
     * Since the goal of this hypervisor is to virtualise and already
     * running operating system, once we initiate VMX, we want to set the
     * RIP and RSP set to the values they were before the core was
     * interrupted by our inter process interrupt. This means once vmx has
     * been initiated, guest operation will continue as normal as if nothing
     * happened.
     */
    HvVmcsWrite64(VMCS_GUEST_RSP, StackPointer);
    HvVmcsWrite64(VMCS_GUEST_RIP, HvArchRestoreState);
}

BOOLEAN
HvVmcsIsApicPresent()
{
    CPUID_EAX_01 features = {0};
    __cpuid((INT*)&features, CPUID_VERSION_INFORMATION);
    return features.CpuidFeatureInformationEdx.ApicOnChip ? TRUE : FALSE;
}

STATIC
BOOLEAN
HvVmcsIsX2ApicMode()
{
    IA32_APIC_BASE_REGISTER apic = {.AsUInt = __readmsr(IA32_APIC_BASE)};
    return apic.EnableX2ApicMode ? TRUE : FALSE;
}

#define QWORD_BIT_COUNT 64

STATIC
VOID
HvVmcsBitmapSetBit(_Inout_ PUINT64 Bitmap, _In_ UINT32 Bit)
{
    UINT32 index = Bit / QWORD_BIT_COUNT;
    UINT32 offset = Bit % QWORD_BIT_COUNT;
    Bitmap[index] |= (1ull << offset);
}

STATIC
VOID
HvVmcsWritePrimaryProcessorControls(_In_ PVCPU Vcpu)
{
    HvVmcsWrite64(
        VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS,
        HvVmcsMsrAdjustControl(
            Vcpu->proc_ctls.AsUInt,
            IA32_VMX_PROCBASED_CTLS));
}

STATIC
VOID
HvVmcsWriteSecondaryProcessControls(_In_ PVCPU Vcpu)
{
    HvVmcsWrite64(
        VMCS_CTRL_SECONDARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS,
        HvVmcsMsrAdjustControl(
            Vcpu->proc_ctls2.AsUInt,
            IA32_VMX_PROCBASED_CTLS2));
}

STATIC
VOID
HvVmcsWritePinBasedControls(_In_ PVCPU Vcpu)
{
    HvVmcsWrite64(
        VMCS_CTRL_PIN_BASED_VM_EXECUTION_CONTROLS,
        HvVmcsMsrAdjustControl(Vcpu->pin_ctls.AsUInt, IA32_VMX_PINBASED_CTLS));
}

STATIC
VOID
HvVmcsWriteExitControls(_In_ PVCPU Vcpu)
{
    HvVmcsWrite64(
        VMCS_CTRL_PRIMARY_VMEXIT_CONTROLS,
        HvVmcsMsrAdjustControl(Vcpu->exit_ctls.AsUInt, IA32_VMX_EXIT_CTLS));
}

STATIC
VOID
HvVmcsWriteEntryControls(_In_ PVCPU Vcpu)
{
    HvVmcsWrite64(
        VMCS_CTRL_VMENTRY_CONTROLS,
        HvVmcsMsrAdjustControl(Vcpu->entry_ctls.AsUInt, IA32_VMX_ENTRY_CTLS));
}

STATIC
VOID
HvVmcsWriteExceptionBitmap(_In_ PVCPU Vcpu)
{
    HvVmcsWrite64(VMCS_CTRL_EXCEPTION_BITMAP, Vcpu->exception_bitmap);
}

STATIC
VOID
HvVmcsWriteMsrBitmap(_In_ PVCPU Vcpu)
{
    HvVmcsWrite64(VMCS_CTRL_MSR_BITMAP_ADDRESS, Vcpu->msr_bitmap_pa);
}

STATIC
VOID
HvVmcsSetControlFields(_In_ PVCPU Vcpu)
{
    /*
     * ActivateSecondaryControls activates the secondary processor-based
     * VM-execution controls. If UseMsrBitmaps is not set, all RDMSR and
     * WRMSR instructions cause vm-exits.
     */
    Vcpu->proc_ctls.ActivateSecondaryControls = TRUE;
    Vcpu->proc_ctls.UseMsrBitmaps = TRUE;
    Vcpu->proc_ctls.Cr3LoadExiting = FALSE;
    Vcpu->proc_ctls.Cr3StoreExiting = FALSE;
    Vcpu->proc_ctls.MovDrExiting = FALSE;

    /* buggy TODO fix! */
    Vcpu->proc_ctls.UnconditionalIoExiting = FALSE;

#if APIC
    if (HvVmcsIsApicPresent()) {
        Vcpu->proc_ctls.UseTprShadow = TRUE;
        Vcpu->proc_ctls.Cr8LoadExiting = FALSE;
        Vcpu->proc_ctls.Cr8StoreExiting = FALSE;
        HvVmcsWrite(VMCS_CTRL_VIRTUAL_APIC_ADDRESS, Vcpu->virtual_apic_pa);
        HvVmcsWrite(VMCS_CTRL_TPR_THRESHOLD, VMX_APIC_TPR_THRESHOLD);
    }
#endif

    Vcpu->proc_ctls2.EnableRdtscp = TRUE;
    Vcpu->proc_ctls2.EnableInvpcid = TRUE;
    Vcpu->proc_ctls2.EnableXsaves = TRUE;

    Vcpu->pin_ctls.NmiExiting = FALSE;

#if DEBUG
    /* For debug mode, in some cases we want to log events that wont cause the
     * buffer to flush too often, in this case preempt into vmx and flush */
    Vcpu->pin_ctls.ActivateVmxPreemptionTimer = TRUE;
#endif

    Vcpu->exit_ctls.AcknowledgeInterruptOnExit = TRUE;
    Vcpu->exit_ctls.HostAddressSpaceSize = TRUE;
    Vcpu->exit_ctls.SaveDebugControls = TRUE;

    /* Ensure we persist the preemption value across guest runtime slices */
    if (Vcpu->pin_ctls.ActivateVmxPreemptionTimer)
        Vcpu->exit_ctls.SaveVmxPreemptionTimerValue = TRUE;

    Vcpu->entry_ctls.Ia32EModeGuest = TRUE;
    Vcpu->entry_ctls.LoadDebugControls = TRUE;

    Vcpu->exception_bitmap |= EXCEPTION_DIVIDED_BY_ZERO;
}

STATIC
VOID
HvVmcsValidateControlFields(_In_ PVCPU Vcpu)
{
    if (!Vcpu->preemption_time) {
        DEBUG_LOG("Disabling preemption timer");
        Vcpu->pin_ctls.ActivateVmxPreemptionTimer = FALSE;
        Vcpu->exit_ctls.SaveVmxPreemptionTimerValue = FALSE;
    }
}

VOID
HvVmcsWriteControlFields(_In_ PVCPU Vcpu)
{
    HvVmcsWritePrimaryProcessorControls(Vcpu);
    HvVmcsWriteSecondaryProcessControls(Vcpu);
    HvVmcsWritePinBasedControls(Vcpu);
    HvVmcsWriteExitControls(Vcpu);
    HvVmcsWriteEntryControls(Vcpu);
    HvVmcsWriteExceptionBitmap(Vcpu);
    HvVmcsWriteMsrBitmap(Vcpu);
    HvVmcsValidateControlFields(Vcpu);
}

NTSTATUS
HvVmcsInitialise(_In_ PVCPU Vcpu, _In_ PVOID StackPointer)
{
    UCHAR status = 0;

    status = __vmx_vmclear(&Vcpu->vmcs_region_pa);
    if (!VMX_OK(status)) {
        DEBUG_ERROR("__vmx_vmclear failed with status %x", status);
        return STATUS_UNSUCCESSFUL;
    }

    status = __vmx_vmptrld(&Vcpu->vmcs_region_pa);
    if (!VMX_OK(status)) {
        if (status == VMX_STATUS_OPERATION_FAILED) {
            DEBUG_ERROR(
                "__vmx_vmptrld failed with status: %llx",
                HvVmcsRead(VMCS_VM_INSTRUCTION_ERROR));
            return STATUS_UNSUCCESSFUL;
        }
        else {
            DEBUG_ERROR("__vmx_vmptrld failed with no status.");
            return STATUS_UNSUCCESSFUL;
        }
    }

    HvVmcsSetControlFields(Vcpu);
    HvVmcsWriteControlFields(Vcpu);
    HvVmcsGuestStateFieldsWrite(StackPointer, Vcpu);
    HvVmcsHostStateFieldsWrite(Vcpu);

    return STATUS_SUCCESS;
}

VOID
HvVmcsSyncConfiguration(_In_ PVCPU Vcpu)
{
    if (Vcpu->pend_updates & HV_VCPU_PENDING_PROC_CTLS_UPDATE) {
        HvVmcsWritePrimaryProcessorControls(Vcpu);
        Vcpu->pend_updates &= ~HV_VCPU_PENDING_PROC_CTLS_UPDATE;
    }

    if (Vcpu->pend_updates & HV_VCPU_PENDING_PROC_CTLS2_UPDATE) {
        HvVmcsWriteSecondaryProcessControls(Vcpu);
        Vcpu->pend_updates &= ~HV_VCPU_PENDING_PROC_CTLS2_UPDATE;
    }

    if (Vcpu->pend_updates & HV_VCPU_PENDING_PIN_CTLS_UPDATE) {
        HvVmcsWritePinBasedControls(Vcpu);
        Vcpu->pend_updates &= ~HV_VCPU_PENDING_PIN_CTLS_UPDATE;
    }

    if (Vcpu->pend_updates & HV_VCPU_PENDING_EXIT_CTLS_UPDATE) {
        HvVmcsWriteExitControls(Vcpu);
        Vcpu->pend_updates &= ~HV_VCPU_PENDING_EXIT_CTLS_UPDATE;
    }

    if (Vcpu->pend_updates & HV_VCPU_PENDING_ENTRY_CTLS_UPDATE) {
        HvVmcsWriteEntryControls(Vcpu);
        Vcpu->pend_updates &= ~HV_VCPU_PENDING_ENTRY_CTLS_UPDATE;
    }

    if (Vcpu->pend_updates & HV_VCPU_PENDING_EXCEPTION_BITMAP_UPDATE) {
        HvVmcsWriteExceptionBitmap(Vcpu);
        Vcpu->pend_updates &= ~HV_VCPU_PENDING_EXCEPTION_BITMAP_UPDATE;
    }

    if (Vcpu->pend_updates & HV_VCPU_PENDING_MSR_BITMAP_UPDATE) {
        HvVmcsWriteMsrBitmap(Vcpu);
        Vcpu->pend_updates &= ~HV_VCPU_PENDING_MSR_BITMAP_UPDATE;
    }
}