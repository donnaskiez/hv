#include "vmcs.h"

#include "driver.h"
#include "segment.h"
#include "ept.h"
#include <intrin.h>

STATIC
UINT32
EncodeField(
	_In_ VMCS_ACCESS_TYPE AccessType,
	_In_ VMCS_TYPE Type,
	_In_ VMCS_WIDTH Width,
	_In_ UINT8 Index 
)
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
	_Out_ PVMCS_GUEST_STATE_FIELDS Fields
)
{
	if (!Fields)
		return;

	/* natural state fields */

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
	Fields->natural_state.sysenter_esp = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_NATURAL, 17);
	Fields->natural_state.sysenter_eip = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_NATURAL, 18);

	/* 64 bit state fields */

	Fields->qword_state.vmcs_link_pointer = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_64, 0);
	Fields->qword_state.debug_control = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_64, 1);
	Fields->qword_state.pat = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_64, 2);
	Fields->qword_state.efer = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_64, 3);
	Fields->qword_state.perf_global_control = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_64, 4);
	Fields->qword_state.bndcfgs = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_64, 5);

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
	Fields->dword_state.smbase = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_32, 18);
	Fields->dword_state.sysenter_cs = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_32, 19);
	
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
	_Out_ PVMCS_HOST_STATE_FIELDS Fields
)
{
	if (!Fields)
		return;

	/* natural */

	Fields->natural_state.cr0 = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_HOST_STATE, VMCS_WIDTH_64, 0);
	Fields->natural_state.cr3 = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_HOST_STATE, VMCS_WIDTH_64, 1);
	Fields->natural_state.cr4 = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_HOST_STATE, VMCS_WIDTH_64, 2);
	Fields->natural_state.rsp = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_HOST_STATE, VMCS_WIDTH_64, 3);
	Fields->natural_state.rip = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_HOST_STATE, VMCS_WIDTH_64, 4);
	Fields->natural_state.fs_base = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_HOST_STATE, VMCS_WIDTH_64, 5);
	Fields->natural_state.gs_base = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_HOST_STATE, VMCS_WIDTH_64, 6);
	Fields->natural_state.tr_base = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_HOST_STATE, VMCS_WIDTH_64, 7);
	Fields->natural_state.gdtr_base = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_HOST_STATE, VMCS_WIDTH_64, 8);
	Fields->natural_state.idtr_base = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_HOST_STATE, VMCS_WIDTH_64, 9);
	Fields->natural_state.ia32_sysenter_esp = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_HOST_STATE, VMCS_WIDTH_64, 10);
	Fields->natural_state.ia32_sysenter_eip = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_HOST_STATE, VMCS_WIDTH_64, 11);
	Fields->natural_state.ia32_perf_global_ctrl = EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_HOST_STATE, VMCS_WIDTH_64, 12);

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
	_In_ PVMCS_CONTROL_STATE_FIELDS Fields
)
{
	if (!Fields)
		return;

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

//NTSTATUS
//InitiateVmcsRegion(
//	_In_ PVMM_STATE VmmState
//)
//{
//	NTSTATUS status = STATUS_SUCCESS;
//	VMCS_GUEST_STATE_FIELDS guest_fields = { 0 };
//	VMCS_HOST_STATE_FIELDS host_fields = { 0 };
//	VMCS_CONTROL_STATE_FIELDS control_fields = { 0 };
//
//	EncodeVmcsGuestStateFields(&guest_fields);
//	EncodeVmcsGuestStateFields(&host_fields);
//	EncodeVmcsGuestStateFields(&control_fields);
//
//	if (__vmx_vmclear(&VmmState->vmcs_region_pa) != VMX_OK || 
//		__vmx_vmptrld(&VmmState->vmcs_region_pa))
//	{
//		DEBUG_LOG("Unable to clear the vmcs region");
//		return STATUS_ABANDONED;
//	}
//
//	__vmx_vmwrite(guest_fields.natural_state.cr0, __readcr0());
//	__vmx_vmwrite(guest_fields.natural_state.cr3, __readcr3());
//	__vmx_vmwrite(guest_fields.natural_state.cr4, __readcr4());
//	__vmx_vmwrite(guest_fields.natural_state.dr7, __readdr(7));
//
//	__vmx_vmwrite(guest_fields.natural_state.rsp, 0);
//	__vmx_vmwrite(guest_fields.natural_state.rip, 0);
//
//	__vmx_vmwrite(guest_fields.natural_state.rflags, __readeflags());
//
//	__vmx_vmwrite(guest_fields.word_state.cs_selector, __read_cs());
//	__vmx_vmwrite(guest_fields.word_state.ds_selector, __read_ds());
//	__vmx_vmwrite(guest_fields.word_state.es_selector, __read_es());
//	__vmx_vmwrite(guest_fields.word_state.fs_selector, __read_fs());
//	__vmx_vmwrite(guest_fields.word_state.gs_selector, __read_gs());
//	__vmx_vmwrite(guest_fields.word_state.ldtr_selector, __read_ldtr());
//	__vmx_vmwrite(guest_fields.word_state.ss_selector, __read_ss());
//	__vmx_vmwrite(guest_fields.word_state.tr_selector, __read_tr());
//
//	__vmx_vmwrite(guest_fields.dword_state.cs_limit, __segmentlimit(__read_cs()));
//	__vmx_vmwrite(guest_fields.dword_state.ds_limit, __segmentlimit(__read_ds()));
//	__vmx_vmwrite(guest_fields.dword_state.es_limit, __segmentlimit(__read_es()));
//	__vmx_vmwrite(guest_fields.dword_state.fs_limit, __segmentlimit(__read_fs()));
//	__vmx_vmwrite(guest_fields.dword_state.gs_limit, __segmentlimit(__read_gs()));
//	__vmx_vmwrite(guest_fields.dword_state.ldtr_limit, __segmentlimit(__read_ldtr()));
//	__vmx_vmwrite(guest_fields.dword_state.ss_limit, __segmentlimit(__read_ss()));
//	__vmx_vmwrite(guest_fields.dword_state.tr_limit, __segmentlimit(__read_tr()));
//
//	__vmx_vmwrite(guest_fields.qword_state.vmcs_link_pointer, ~0ull);
//
//	__vmx_vmwrite(guest_fields.qword_state.debug_control, __readmsr(MSR_IA32_DEBUGCTL) & 0xffffffff);
//
//	__vmx_vmwrite(host_fields.natural_state.cr0, __readcr0());
//	__vmx_vmwrite(host_fields.natural_state.cr3, __readcr3());
//	__vmx_vmwrite(host_fields.natural_state.cr4, __readcr4());
//
//	__vmx_vmwrite(host_fields.word_state.cs_selector, __read_cs() & 0xf8);
//	__vmx_vmwrite(host_fields.word_state.ds_selector, __read_ds() & 0xf8);
//	__vmx_vmwrite(host_fields.word_state.es_selector, __read_es() & 0xf8);
//	__vmx_vmwrite(host_fields.word_state.fs_selector, __read_fs() & 0xf8);
//	__vmx_vmwrite(host_fields.word_state.gs_selector, __read_gs() & 0xf8);
//	__vmx_vmwrite(host_fields.word_state.ss_selector, __read_ss() & 0xf8);
//	__vmx_vmwrite(host_fields.word_state.tr_selector, __read_tr() & 0xf8);
//
//	__vmx_vmwrite(control_fields.qword_state.tsc_offset, 0);
//	__vmx_vmwrite(control_fields.dword_state.pagefault_error_code_mask, 0);
//	__vmx_vmwrite(control_fields.dword_state.pagefault_error_code_match, 0);
//	__vmx_vmwrite(control_fields.dword_state.vmexit_msr_load_count, 0);
//	__vmx_vmwrite(control_fields.dword_state.vmexit_msr_store_count, 0);
//	__vmx_vmwrite(control_fields.dword_state.vmentry_msr_load_count, 0);
//	__vmx_vmwrite(control_fields.dword_state.vmentry_interruption_info, 0);
//}

BOOLEAN
GetSegmentDescriptor(PSEGMENT_SELECTOR SegmentSelector,
	USHORT            Selector,
	PUCHAR            GdtBase)
{
	PSEGMENT_DESCRIPTOR SegDesc;

	if (!SegmentSelector)
		return FALSE;

	if (Selector & 0x4)
	{
		return FALSE;
	}

	SegDesc = (PSEGMENT_DESCRIPTOR)((PUCHAR)GdtBase + (Selector & ~0x7));

	SegmentSelector->SEL = Selector;
	SegmentSelector->BASE = SegDesc->BASE0 | SegDesc->BASE1 << 16 | SegDesc->BASE2 << 24;
	SegmentSelector->LIMIT = SegDesc->LIMIT0 | (SegDesc->LIMIT1ATTR1 & 0xf) << 16;
	SegmentSelector->ATTRIBUTES.UCHARs = SegDesc->ATTR0 | (SegDesc->LIMIT1ATTR1 & 0xf0) << 4;

	if (!(SegDesc->ATTR0 & 0x10))
	{ // LA_ACCESSED
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
AdjustControls(ULONG Ctl, ULONG Msr)
{
	MSR MsrValue = { 0 };

	MsrValue.Content = __readmsr(Msr);
	Ctl &= MsrValue.High; /* bit == 0 in high word ==> must be zero */
	Ctl |= MsrValue.Low;  /* bit == 1 in low word  ==> must be one  */
	return Ctl;
}

VOID
FillGuestSelectorData(
	PVOID  GdtBase,
	ULONG  Segreg,
	USHORT Selector)
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

BOOLEAN
SetupVmcs(PVMM_STATE GuestState, PEPTP EPTP)
{
	BOOLEAN Status = FALSE;

	// Load Extended Page Table Pointer
	//__vmx_vmwrite(EPT_POINTER, EPTP->All);

	ULONG64          GdtBase = 0;
	SEGMENT_SELECTOR SegmentSelector = { 0 };

	if (__vmx_vmclear(&GuestState->vmcs_region_pa) != VMX_OK || 
		__vmx_vmptrld(&GuestState->vmcs_region_pa))
	{
		DEBUG_LOG("Unable to clear the vmcs region");
		return STATUS_ABANDONED;
	}

	__vmx_vmwrite(HOST_ES_SELECTOR, __read_es() & 0xF8);
	__vmx_vmwrite(HOST_CS_SELECTOR, __read_cs() & 0xF8);
	__vmx_vmwrite(HOST_SS_SELECTOR, __read_ss() & 0xF8);
	__vmx_vmwrite(HOST_DS_SELECTOR, __read_ds() & 0xF8);
	__vmx_vmwrite(HOST_FS_SELECTOR, __read_fs() & 0xF8);
	__vmx_vmwrite(HOST_GS_SELECTOR, __read_gs() & 0xF8);
	__vmx_vmwrite(HOST_TR_SELECTOR, __read_tr() & 0xF8);

	//
	// Setting the link pointer to the required value for 4KB VMCS
	//
	__vmx_vmwrite(VMCS_LINK_POINTER, ~0ULL);

	__vmx_vmwrite(GUEST_IA32_DEBUGCTL, __readmsr(MSR_IA32_DEBUGCTL) & 0xFFFFFFFF);
	__vmx_vmwrite(GUEST_IA32_DEBUGCTL_HIGH, __readmsr(MSR_IA32_DEBUGCTL) >> 32);

	/* Time-stamp counter offset */
	__vmx_vmwrite(TSC_OFFSET, 0);
	__vmx_vmwrite(TSC_OFFSET_HIGH, 0);

	__vmx_vmwrite(PAGE_FAULT_ERROR_CODE_MASK, 0);
	__vmx_vmwrite(PAGE_FAULT_ERROR_CODE_MATCH, 0);

	__vmx_vmwrite(VM_EXIT_MSR_STORE_COUNT, 0);
	__vmx_vmwrite(VM_EXIT_MSR_LOAD_COUNT, 0);

	__vmx_vmwrite(VM_ENTRY_MSR_LOAD_COUNT, 0);
	__vmx_vmwrite(VM_ENTRY_INTR_INFO_FIELD, 0);

	FillGuestSelectorData(__get_gdt_base, ES, __read_es());
	FillGuestSelectorData(__get_gdt_base, CS, __read_cs());
	FillGuestSelectorData(__get_gdt_base, SS, __read_ss());
	FillGuestSelectorData(__get_gdt_base, DS, __read_ds());
	FillGuestSelectorData(__get_gdt_base, FS, __read_fs());
	FillGuestSelectorData(__get_gdt_base, GS, __read_gs());
	FillGuestSelectorData(__get_gdt_base, LDTR, __read_ldtr());
	FillGuestSelectorData(__get_gdt_base, TR, __read_tr());

	__vmx_vmwrite(GUEST_FS_BASE, __readmsr(MSR_FS_BASE));
	__vmx_vmwrite(GUEST_GS_BASE, __readmsr(MSR_GS_BASE));

	__vmx_vmwrite(GUEST_INTERRUPTIBILITY_INFO, 0);
	__vmx_vmwrite(GUEST_ACTIVITY_STATE, 0); // Active state

	__vmx_vmwrite(CPU_BASED_VM_EXEC_CONTROL, AdjustControls(CPU_BASED_HLT_EXITING | CPU_BASED_ACTIVATE_SECONDARY_CONTROLS, MSR_IA32_VMX_PROCBASED_CTLS));
	__vmx_vmwrite(SECONDARY_VM_EXEC_CONTROL, AdjustControls(CPU_BASED_CTL2_RDTSCP /* | CPU_BASED_CTL2_ENABLE_EPT*/, MSR_IA32_VMX_PROCBASED_CTLS2));

	__vmx_vmwrite(PIN_BASED_VM_EXEC_CONTROL, AdjustControls(0, MSR_IA32_VMX_PINBASED_CTLS));
	__vmx_vmwrite(VM_EXIT_CONTROLS, AdjustControls(VM_EXIT_IA32E_MODE | VM_EXIT_ACK_INTR_ON_EXIT, MSR_IA32_VMX_EXIT_CTLS));
	__vmx_vmwrite(VM_ENTRY_CONTROLS, AdjustControls(VM_ENTRY_IA32E_MODE, MSR_IA32_VMX_ENTRY_CTLS));

	__vmx_vmwrite(CR3_TARGET_COUNT, 0);
	__vmx_vmwrite(CR3_TARGET_VALUE0, 0);
	__vmx_vmwrite(CR3_TARGET_VALUE1, 0);
	__vmx_vmwrite(CR3_TARGET_VALUE2, 0);
	__vmx_vmwrite(CR3_TARGET_VALUE3, 0);

	__vmx_vmwrite(GUEST_CR0, __readcr0());
	__vmx_vmwrite(GUEST_CR3, __readcr3());
	__vmx_vmwrite(GUEST_CR4, __readcr4());

	__vmx_vmwrite(GUEST_DR7, 0x400);

	__vmx_vmwrite(HOST_CR0, __readcr0());
	__vmx_vmwrite(HOST_CR3, __readcr3());
	__vmx_vmwrite(HOST_CR4, __readcr4());

	__vmx_vmwrite(GUEST_GDTR_BASE, GetGdtBase());
	__vmx_vmwrite(GUEST_IDTR_BASE, GetIdtBase());
	__vmx_vmwrite(GUEST_GDTR_LIMIT, GetGdtLimit());
	__vmx_vmwrite(GUEST_IDTR_LIMIT, GetIdtLimit());

	__vmx_vmwrite(GUEST_RFLAGS, GetRflags());

	__vmx_vmwrite(GUEST_SYSENTER_CS, __readmsr(MSR_IA32_SYSENTER_CS));
	__vmx_vmwrite(GUEST_SYSENTER_EIP, __readmsr(MSR_IA32_SYSENTER_EIP));
	__vmx_vmwrite(GUEST_SYSENTER_ESP, __readmsr(MSR_IA32_SYSENTER_ESP));

	GetSegmentDescriptor(&SegmentSelector, __read_tr(), (PUCHAR)GetGdtBase());
	__vmx_vmwrite(HOST_TR_BASE, SegmentSelector.BASE);

	__vmx_vmwrite(HOST_FS_BASE, __readmsr(MSR_FS_BASE));
	__vmx_vmwrite(HOST_GS_BASE, __readmsr(MSR_GS_BASE));

	__vmx_vmwrite(HOST_GDTR_BASE, GetGdtBase());
	__vmx_vmwrite(HOST_IDTR_BASE, GetIdtBase());

	__vmx_vmwrite(HOST_IA32_SYSENTER_CS, __readmsr(MSR_IA32_SYSENTER_CS));
	__vmx_vmwrite(HOST_IA32_SYSENTER_EIP, __readmsr(MSR_IA32_SYSENTER_EIP));
	__vmx_vmwrite(HOST_IA32_SYSENTER_ESP, __readmsr(MSR_IA32_SYSENTER_ESP));

	//
	// left here just for test
	//
	__vmx_vmwrite(GUEST_RSP, (ULONG64)guest_virtual_memory_address); // setup guest sp
	__vmx_vmwrite(GUEST_RIP, (ULONG64)guest_virtual_memory_address); // setup guest ip

	__vmx_vmwrite(HOST_RSP, ((ULONG64)GuestState->vmm_stack + VMM_STACK_SIZE - 1));
	__vmx_vmwrite(HOST_RIP, (ULONG64)AsmVmexitHandler);

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
		__vmx_exit_and_restore_state();

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