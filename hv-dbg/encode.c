#include "common.h"

STATIC
UINT32
EncodeField(_In_ VMCS_ACCESS_TYPE AccessType,
            _In_ VMCS_TYPE        Type,
            _In_ VMCS_WIDTH       Width,
            _In_ UINT8            Index)
{
        VMCS_ENCODING encoding = {.bits.access_type = AccessType,
                                  .bits.type        = Type,
                                  .bits.width       = Width,
                                  .bits.index       = Index};

        return encoding.address;
}

VOID
EncodeVmcsGuestStateFields(_Out_ PVMCS_GUEST_STATE_FIELDS Fields)
{
        Fields->natural_state.cr0 =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_NATURAL, 0);
        Fields->natural_state.cr3 =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_NATURAL, 1);
        Fields->natural_state.cr4 =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_NATURAL, 2);
        Fields->natural_state.es_base =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_NATURAL, 3);
        Fields->natural_state.cs_base =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_NATURAL, 4);
        Fields->natural_state.ss_base =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_NATURAL, 5);
        Fields->natural_state.ds_base =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_NATURAL, 6);
        Fields->natural_state.fs_base =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_NATURAL, 7);
        Fields->natural_state.gs_base =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_NATURAL, 8);
        Fields->natural_state.ldtr_base =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_NATURAL, 9);
        Fields->natural_state.tr_base =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_NATURAL, 10);
        Fields->natural_state.gdtr_base =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_NATURAL, 11);
        Fields->natural_state.idtr_base =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_NATURAL, 12);
        Fields->natural_state.dr7 =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_NATURAL, 13);
        Fields->natural_state.rsp =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_NATURAL, 14);
        Fields->natural_state.rip =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_NATURAL, 15);
        Fields->natural_state.rflags =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_NATURAL, 16);
        Fields->natural_state.pending_debug_exceptions =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_NATURAL, 17);
        Fields->natural_state.sysenter_esp =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_NATURAL, 18);
        Fields->natural_state.sysenter_eip =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_NATURAL, 19);

        /* 64 bit state fields */

        Fields->qword_state.vmcs_link_pointer =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_64, 0);
        Fields->qword_state.debug_control =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_64, 1);
        Fields->qword_state.pat =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_64, 2);
        Fields->qword_state.efer =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_64, 3);
        Fields->qword_state.perf_global_control =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_64, 4);
        Fields->qword_state.pdpte0 =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_64, 5);
        Fields->qword_state.pdpte1 =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_64, 6);
        Fields->qword_state.pdpte2 =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_64, 7);
        Fields->qword_state.pdpte3 =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_64, 8);

        /* 32 bit state fields */

        Fields->dword_state.es_limit =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_32, 0);
        Fields->dword_state.cs_limit =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_32, 1);
        Fields->dword_state.ss_limit =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_32, 2);
        Fields->dword_state.ds_limit =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_32, 3);
        Fields->dword_state.fs_limit =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_32, 4);
        Fields->dword_state.gs_limit =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_32, 5);
        Fields->dword_state.ldtr_limit =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_32, 6);
        Fields->dword_state.tr_limit =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_32, 7);
        Fields->dword_state.gdtr_limit =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_32, 8);
        Fields->dword_state.idtr_limit =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_32, 9);
        Fields->dword_state.es_access_rights =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_32, 10);
        Fields->dword_state.cs_access_rights =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_32, 11);
        Fields->dword_state.ss_access_rights =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_32, 12);
        Fields->dword_state.ds_access_rights =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_32, 13);
        Fields->dword_state.fs_access_rights =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_32, 14);
        Fields->dword_state.gs_access_rights =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_32, 15);
        Fields->dword_state.ldtr_access_rights =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_32, 16);
        Fields->dword_state.tr_access_rights =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_32, 17);
        Fields->dword_state.interruptibility_state =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_32, 18);
        Fields->dword_state.activity_state =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_32, 19);
        Fields->dword_state.smbase =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_32, 20);
        Fields->dword_state.sysenter_cs =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_32, 21);
        Fields->dword_state.vmx_preemption_timer_value =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_32, 23);

        /* 16 bit fields */

        Fields->word_state.es_selector =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_16, 0);
        Fields->word_state.cs_selector =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_16, 1);
        Fields->word_state.ss_selector =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_16, 2);
        Fields->word_state.ds_selector =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_16, 3);
        Fields->word_state.fs_selector =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_16, 4);
        Fields->word_state.gs_selector =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_16, 5);
        Fields->word_state.ldtr_selector =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_16, 6);
        Fields->word_state.tr_selector =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_16, 7);
        Fields->word_state.interrupt_status =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_16, 8);
        Fields->word_state.pml_index =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_GUEST_STATE, VMCS_WIDTH_16, 9);
}

VOID
EncodeVmcsHostStateFields(_Out_ PVMCS_HOST_STATE_FIELDS Fields)
{
        /* natural */

        Fields->natural_state.cr0 =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_HOST_STATE, VMCS_WIDTH_NATURAL, 0);
        Fields->natural_state.cr3 =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_HOST_STATE, VMCS_WIDTH_NATURAL, 1);
        Fields->natural_state.cr4 =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_HOST_STATE, VMCS_WIDTH_NATURAL, 2);
        Fields->natural_state.fs_base =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_HOST_STATE, VMCS_WIDTH_NATURAL, 3);
        Fields->natural_state.gs_base =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_HOST_STATE, VMCS_WIDTH_NATURAL, 4);
        Fields->natural_state.tr_base =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_HOST_STATE, VMCS_WIDTH_NATURAL, 5);
        Fields->natural_state.gdtr_base =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_HOST_STATE, VMCS_WIDTH_NATURAL, 6);
        Fields->natural_state.idtr_base =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_HOST_STATE, VMCS_WIDTH_NATURAL, 7);
        Fields->natural_state.ia32_sysenter_esp =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_HOST_STATE, VMCS_WIDTH_NATURAL, 8);
        Fields->natural_state.ia32_sysenter_eip =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_HOST_STATE, VMCS_WIDTH_NATURAL, 9);
        Fields->natural_state.rsp =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_HOST_STATE, VMCS_WIDTH_NATURAL, 10);
        Fields->natural_state.rip =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_HOST_STATE, VMCS_WIDTH_NATURAL, 11);

        /* 64 bit */

        Fields->qword_state.pat =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_HOST_STATE, VMCS_WIDTH_64, 0);
        Fields->qword_state.efer =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_HOST_STATE, VMCS_WIDTH_64, 1);
        Fields->qword_state.ia32_perf_global_ctrl =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_HOST_STATE, VMCS_WIDTH_64, 2);

        /* 16 bit */

        Fields->word_state.es_selector =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_HOST_STATE, VMCS_WIDTH_16, 0);
        Fields->word_state.cs_selector =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_HOST_STATE, VMCS_WIDTH_16, 1);
        Fields->word_state.ss_selector =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_HOST_STATE, VMCS_WIDTH_16, 2);
        Fields->word_state.ds_selector =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_HOST_STATE, VMCS_WIDTH_16, 3);
        Fields->word_state.fs_selector =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_HOST_STATE, VMCS_WIDTH_16, 4);
        Fields->word_state.gs_selector =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_HOST_STATE, VMCS_WIDTH_16, 5);
        Fields->word_state.tr_selector =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_HOST_STATE, VMCS_WIDTH_16, 6);

        /* 32 bit */

        Fields->dword_state.ia32_sysenter_cs =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_HOST_STATE, VMCS_WIDTH_32, 0);
}

VOID
EncodeVmcsControlStateFields(_Out_ PVMCS_CONTROL_STATE_FIELDS Fields)
{
        /* natural state */

        Fields->natural_state.cr0_guest_host_mask =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_CONTROL, VMCS_WIDTH_NATURAL, 0);
        Fields->natural_state.cr4_guest_host_mask =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_CONTROL, VMCS_WIDTH_NATURAL, 1);
        Fields->natural_state.cr0_read_shadow =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_CONTROL, VMCS_WIDTH_NATURAL, 2);
        Fields->natural_state.cr4_read_shadow =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_CONTROL, VMCS_WIDTH_NATURAL, 3);
        Fields->natural_state.cr3_target_value_0 =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_CONTROL, VMCS_WIDTH_NATURAL, 4);
        Fields->natural_state.cr3_target_value_1 =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_CONTROL, VMCS_WIDTH_NATURAL, 5);
        Fields->natural_state.cr3_target_value_2 =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_CONTROL, VMCS_WIDTH_NATURAL, 6);
        Fields->natural_state.cr3_target_value_3 =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_CONTROL, VMCS_WIDTH_NATURAL, 7);

        /* 64bit state */

        Fields->qword_state.io_bitmap_a_address =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_CONTROL, VMCS_WIDTH_64, 0);
        Fields->qword_state.io_bitmap_b_address =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_CONTROL, VMCS_WIDTH_64, 1);
        Fields->qword_state.msr_bitmap_address =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_CONTROL, VMCS_WIDTH_64, 2);
        Fields->qword_state.vmexit_msr_store_address =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_CONTROL, VMCS_WIDTH_64, 3);
        Fields->qword_state.vmexit_msr_load_address =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_CONTROL, VMCS_WIDTH_64, 4);
        Fields->qword_state.vmentry_msr_load_address =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_CONTROL, VMCS_WIDTH_64, 5);
        Fields->qword_state.executive_vmcs_pointer =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_CONTROL, VMCS_WIDTH_64, 6);
        Fields->qword_state.pml_address =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_CONTROL, VMCS_WIDTH_64, 7);
        Fields->qword_state.tsc_offset =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_CONTROL, VMCS_WIDTH_64, 8);
        Fields->qword_state.virtual_apic_address =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_CONTROL, VMCS_WIDTH_64, 9);
        Fields->qword_state.apic_access_address =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_CONTROL, VMCS_WIDTH_64, 10);
        Fields->qword_state.posted_interrupt_descriptor_address =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_CONTROL, VMCS_WIDTH_64, 11);
        Fields->qword_state.vmfunc_controls =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_CONTROL, VMCS_WIDTH_64, 12);
        Fields->qword_state.ept_pointer =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_CONTROL, VMCS_WIDTH_64, 13);
        Fields->qword_state.eoi_exit_bitmap_0 =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_CONTROL, VMCS_WIDTH_64, 14);
        Fields->qword_state.eoi_exit_bitmap_1 =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_CONTROL, VMCS_WIDTH_64, 15);
        Fields->qword_state.eoi_exit_bitmap_2 =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_CONTROL, VMCS_WIDTH_64, 16);
        Fields->qword_state.eoi_exit_bitmap_3 =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_CONTROL, VMCS_WIDTH_64, 17);
        Fields->qword_state.ept_pointer_list_address =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_CONTROL, VMCS_WIDTH_64, 18);
        Fields->qword_state.vmread_bitmap_address =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_CONTROL, VMCS_WIDTH_64, 19);
        Fields->qword_state.vmwrite_bitmap_address =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_CONTROL, VMCS_WIDTH_64, 20);
        Fields->qword_state.virtualization_exception_info_address =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_CONTROL, VMCS_WIDTH_64, 21);
        Fields->qword_state.xss_exiting_bitmap =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_CONTROL, VMCS_WIDTH_64, 22);
        Fields->qword_state.encls_exiting_bitmap =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_CONTROL, VMCS_WIDTH_64, 23);
        Fields->qword_state.tsc_multiplier =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_CONTROL, VMCS_WIDTH_64, 25);

        /* 32 bit state */

        Fields->dword_state.pin_based_vm_execution_controls =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_CONTROL, VMCS_WIDTH_32, 0);
        Fields->dword_state.processor_based_vm_execution_controls =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_CONTROL, VMCS_WIDTH_32, 1);
        Fields->dword_state.exception_bitmap =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_CONTROL, VMCS_WIDTH_32, 2);
        Fields->dword_state.pagefault_error_code_mask =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_CONTROL, VMCS_WIDTH_32, 3);
        Fields->dword_state.pagefault_error_code_match =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_CONTROL, VMCS_WIDTH_32, 4);
        Fields->dword_state.cr3_target_count =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_CONTROL, VMCS_WIDTH_32, 5);
        Fields->dword_state.vmexit_controls =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_CONTROL, VMCS_WIDTH_32, 6);
        Fields->dword_state.vmexit_msr_store_count =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_CONTROL, VMCS_WIDTH_32, 7);
        Fields->dword_state.vmexit_msr_load_count =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_CONTROL, VMCS_WIDTH_32, 8);
        Fields->dword_state.vmentry_controls =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_CONTROL, VMCS_WIDTH_32, 9);
        Fields->dword_state.vmentry_msr_load_count =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_CONTROL, VMCS_WIDTH_32, 10);
        Fields->dword_state.vmentry_interruption_info =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_CONTROL, VMCS_WIDTH_32, 11);
        Fields->dword_state.vmentry_exception_error_code =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_CONTROL, VMCS_WIDTH_32, 12);
        Fields->dword_state.vmentry_instruction_length =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_CONTROL, VMCS_WIDTH_32, 13);
        Fields->dword_state.tpr_threshold =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_CONTROL, VMCS_WIDTH_32, 14);
        Fields->dword_state.secondary_processor_based_vm_execution_controls =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_CONTROL, VMCS_WIDTH_32, 15);
        Fields->dword_state.ple_gap =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_CONTROL, VMCS_WIDTH_32, 16);
        Fields->dword_state.ple_window =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_CONTROL, VMCS_WIDTH_32, 17);

        /* 16 bit state */

        Fields->word_state.virtual_processor_identifier =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_CONTROL, VMCS_WIDTH_16, 0);
        Fields->word_state.posted_interrupt_notification_vector =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_CONTROL, VMCS_WIDTH_16, 1);
        Fields->word_state.eptp_index =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_CONTROL, VMCS_WIDTH_16, 2);
}

VOID
EncodeVmcsExitStateFields(_Out_ PVMCS_EXIT_STATE_FIELDS Fields)
{
        Fields->natural_state.exit_qualification =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_EXIT_INFORMATION, VMCS_WIDTH_NATURAL, 0);
        Fields->natural_state.io_rcx =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_EXIT_INFORMATION, VMCS_WIDTH_NATURAL, 1);
        Fields->natural_state.io_rsx =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_EXIT_INFORMATION, VMCS_WIDTH_NATURAL, 2);
        Fields->natural_state.io_rdi =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_EXIT_INFORMATION, VMCS_WIDTH_NATURAL, 3);
        Fields->natural_state.io_rip =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_EXIT_INFORMATION, VMCS_WIDTH_NATURAL, 4);
        Fields->natural_state.guest_linear_address =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_EXIT_INFORMATION, VMCS_WIDTH_NATURAL, 5);

        Fields->qword_state.guest_physical_address =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_EXIT_INFORMATION, VMCS_WIDTH_64, 0);

        Fields->dword_state.instruction_error =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_EXIT_INFORMATION, VMCS_WIDTH_32, 0);
        Fields->dword_state.reason =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_EXIT_INFORMATION, VMCS_WIDTH_32, 1);
        Fields->dword_state.interruption_info =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_EXIT_INFORMATION, VMCS_WIDTH_32, 2);
        Fields->dword_state.interruption_error_code =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_EXIT_INFORMATION, VMCS_WIDTH_32, 3);
        Fields->dword_state.idt_vectoring_info =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_EXIT_INFORMATION, VMCS_WIDTH_32, 4);
        Fields->dword_state.idt_vectoring_error_code =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_EXIT_INFORMATION, VMCS_WIDTH_32, 5);
        Fields->dword_state.instruction_length =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_EXIT_INFORMATION, VMCS_WIDTH_32, 6);
        Fields->dword_state.instruction_info =
            EncodeField(VMCS_ACCESS_FULL, VMCS_TYPE_EXIT_INFORMATION, VMCS_WIDTH_32, 7);
}