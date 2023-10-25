#ifndef VMCS_H
#define VMCS_H

#include <ntifs.h>

typedef struct _NATURAL_STATE
{
	UINT64 cr0;
	UINT64 cr3;
	UINT64 cr4;
	UINT64 es_base;
	UINT64 cs_base;
	UINT64 ss_base;
	UINT64 ds_base;
	UINT64 fs_base;
	UINT64 gs_base;
	UINT64 ldtr_base;
	UINT64 tr_base;
	UINT64 gdtr_base;
	UINT64 idtr_base;
	UINT64 dr7;
	UINT64 rsp;
	UINT64 rip;
	UINT64 rflags;
	UINT64 sysenter_esp;
	UINT64 sysenter_eip;

}NATURAL_STATE, * PNATURAL_STATE;

typedef struct _QWORD_BIT_STATE
{
	UINT64 vmcs_link_pointer;
	UINT64 debug_control;
	UINT64 pat;
	UINT64 efer;
	UINT64 perf_global_control;
	UINT64 bndcfgs;

}QWORD_BIT_STATE, * PQWORD_BIT_STATE;

typedef struct _DWORD_BIT_STATE
{
	UINT32 es_limit;
	UINT32 cs_limit;
	UINT32 ss_limit;
	UINT32 ds_limit;
	UINT32 fs_limit;
	UINT32 gs_limit;
	UINT32 ldtr_limit;
	UINT32 tr_limit;
	UINT32 gdtr_limit;
	UINT32 idtr_limit;
	UINT32 es_access_rights;
	UINT32 cs_access_rights;
	UINT32 ss_access_rights;
	UINT32 ds_access_rights;
	UINT32 fs_access_rights;
	UINT32 gs_access_rights;
	UINT32 ldtr_access_rights;
	UINT32 tr_access_rights;
	UINT32 smbase;
	UINT32 sysenter_cs;

}DWORD_BIT_STATE, * PDWORD_BIT_STATE;

typedef struct _WORD_BIT_STATE
{
	UINT16 es_selector;
	UINT16 cs_selector;
	UINT16 ss_selector;
	UINT16 ds_selector;
	UINT16 fs_selector;
	UINT16 gs_selector;
	UINT16 ldtr_selector;
	UINT16 tr_selector;

}WORD_BIT_STATE, * PWORD_BIT_STATE;

typedef struct _VMCS_GUEST_STATE_FIELDS
{
	NATURAL_STATE natural_state;
	QWORD_BIT_STATE qword_state;
	DWORD_BIT_STATE dword_state;
	WORD_BIT_STATE word_state;


}VMCS_GUEST_STATE_FIELDS, * PVMCS_GUEST_STATE_FIELDS;

/*
* Host state area
*/
typedef struct _HOST_WORD_BIT_STATE
{
	UINT16 es_selector;
	UINT16 cs_selector;
	UINT16 ss_selector;
	UINT16 ds_selector;
	UINT16 fs_selector;
	UINT16 gs_selector;
	UINT16 tr_selector;

}HOST_WORD_BIT_STATE, * PHOST_WORD_BIT_STATE;

typedef struct _HOST_NATURAL_BIT_STATE
{
	UINT64 cr0;
	UINT64 cr3;
	UINT64 cr4;
	UINT64 rsp;
	UINT64 rip;
	UINT64 fs_base;
	UINT64 gs_base;
	UINT64 tr_base;
	UINT64 gdtr_base;
	UINT64 idtr_base;
	UINT64 ia32_sysenter_esp;
	UINT64 ia32_sysenter_eip;
	UINT64 ia32_perf_global_ctrl;

}HOST_NATURAL_BIT_STATE, *PHOST_NATURAL_BIT_STATE;

typedef struct _HOST_DWORD_BIT_STATE
{
	UINT32 ia32_sysenter_cs;

}HOST_DWORD_BIT_STATE, *PHOST_DWORD_BIT_STATE;

typedef struct _VMCS_HOST_STATE_FIELDS
{
	HOST_WORD_BIT_STATE word_state;
	HOST_DWORD_BIT_STATE dword_state;
	HOST_NATURAL_BIT_STATE natural_state;

}VMCS_HOST_STATE_FIELDS, *PVMCS_HOST_STATE_FIELDS;

typedef struct _CONTROL_QWORD_BIT_STATE
{
	UINT64 io_bitmap_a_address;
	UINT64 io_bitmap_b_address;
	UINT64 msr_bitmap_address;
	UINT64 vmexit_msr_store_address;
	UINT64 vmexit_msr_load_address;
	UINT64 vmentry_msr_load_address;
	UINT64 executive_vmcs_pointer;
	UINT64 pml_address;
	UINT64 tsc_offset;
	UINT64 virtual_apic_address;
	UINT64 apic_access_address;
	UINT64 posted_interrupt_descriptor_address;
	UINT64 vmfunc_controls;
	UINT64 ept_pointer;
	UINT64 eoi_exit_bitmap_0;
	UINT64 eoi_exit_bitmap_1;
	UINT64 eoi_exit_bitmap_2;
	UINT64 eoi_exit_bitmap_3;
	UINT64 ept_pointer_list_address;
	UINT64 vmread_bitmap_address;
	UINT64 vmwrite_bitmap_address;
	UINT64 virtualization_exception_info_address;
	UINT64 xss_exiting_bitmap;
	UINT64 encls_exiting_bitmap;
	UINT64 tsc_multiplier;

} CONTROL_QWORD_BIT_STATE, * PCONTROL_QWORD_BIT_STATE;

typedef struct _CONTROL_DWORD_BIT_STATE
{
	UINT32 pin_based_vm_execution_controls;
	UINT32 processor_based_vm_execution_controls;
	UINT32 exception_bitmap;
	UINT32 pagefault_error_code_mask;
	UINT32 pagefault_error_code_match;
	UINT32 cr3_target_count;
	UINT32 vmexit_controls;
	UINT32 vmexit_msr_store_count;
	UINT32 vmexit_msr_load_count;
	UINT32 vmentry_controls;
	UINT32 vmentry_msr_load_count;
	UINT32 vmentry_interruption_info;
	UINT32 vmentry_exception_error_code;
	UINT32 vmentry_instruction_length;
	UINT32 tpr_threshold;
	UINT32 secondary_processor_based_vm_execution_controls;
	UINT32 ple_gap;
	UINT32 ple_window;

} CONTROL_DWORD_BIT_STATE, *PCONTROL_DWORD_BIT_STATE;

typedef struct _CONTROL_WORD_BIT_STATE
{
	UINT16 virtual_processor_identifier;
	UINT16 posted_interrupt_notification_vector;
	UINT16 eptp_index;

} CONTROL_WORD_BIT_STATE, * PCONTROL_WORD_BIT_STATE;

typedef struct _CONTROL_NATURAL_BIT_STATE
{
	UINT64 cr0_guest_host_mask;
	UINT64 cr4_guest_host_mask;
	UINT64 cr0_read_shadow;
	UINT64 cr4_read_shadow;
	UINT64 cr3_target_value_0;
	UINT64 cr3_target_value_1;
	UINT64 cr3_target_value_2;
	UINT64 cr3_target_value_3;

} CONTROL_NATURAL_BIT_STATE, *PCONTROL_NATURAL_BIT_STATE;

typedef struct _VMCS_CONTROL_STATE_FIELDS
{
	CONTROL_WORD_BIT_STATE word_state;
	CONTROL_DWORD_BIT_STATE dword_state;
	CONTROL_QWORD_BIT_STATE qword_state;
	CONTROL_NATURAL_BIT_STATE natural_state;

}VMCS_CONTROL_STATE_FIELDS, *PVMCS_CONTROL_STATE_FIELDS;

/*
* 24.11.2
*/
typedef union _VMCS_ENCODING
{
	struct
	{
		UINT32 access_type : 1;
		UINT32 index : 9;
		UINT32 type : 2;
		UINT32 reserved1 : 1;
		UINT32 width : 2;
		UINT32 reserved2 : 17;
	}bits;

	UINT32 address;

}VMCS_ENCODING, * PVMCS_ENCODING;

typedef enum _VMCS_ACCESS_TYPE
{
	VMCS_ACCESS_FULL = 0,
	VMCS_ACCESS_HIGH = 1

}VMCS_ACCESS_TYPE;

typedef enum _VMCS_TYPE
{
	VMCS_TYPE_CONTROL = 0,
	VMCS_TYPE_EXIT_INFORMATION = 1,
	VMCS_TYPE_GUEST_STATE = 2,
	VMCS_TYPE_HOST_STATE = 3

}VMCS_TYPE;

typedef enum _VMCS_WIDTH
{
	VMCS_WIDTH_16 = 0,
	VMCS_WIDTH_64 = 1,
	VMCS_WIDTH_32 = 2,
	VMCS_WIDTH_NATURAL = 3

}VMCS_WIDTH;

#endif