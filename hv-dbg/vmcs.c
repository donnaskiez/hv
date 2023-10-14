#include "vmcs.h"

#include "driver.h"
#include "segment.h"

#include <intrin.h>

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
		UINT32 reserved : 1;
		UINT32 width : 2;
		UINT32 reserved : 17;
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

}NATURAL_STATE, *PNATURAL_STATE;
typedef struct _QWORD_BIT_STATE
{
	UINT64 vmcs_link_pointer;
	UINT64 debug_control;
	UINT64 pat;
	UINT64 efer;
	UINT64 perf_global_control;
	UINT64 bndcfgs;

}QWORD_BIT_STATE, *PQWORD_BIT_STATE;
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

}DWORD_BIT_STATE, *PDWORD_BIT_STATE;
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

}WORD_BIT_STATE, *PWORD_BIT_STATE;
typedef struct _VMCS_GUEST_STATE_FIELDS
{
	NATURAL_STATE natural_state;
	QWORD_BIT_STATE qword_state;
	DWORD_BIT_STATE dword_state;
	WORD_BIT_STATE word_state;


}VMCS_GUEST_STATE_FIELDS, *PVMCS_GUEST_STATE_FIELDS;

STATIC
VOID
EncodeVmcsStateFields(
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

NTSTATUS
InitiateVmcsRegion(
	_Inout_ PVMM_STATE VmmState
)
{
	NTSTATUS status = STATUS_SUCCESS;
	VMCS_GUEST_STATE_FIELDS guest_fields = { 0 };

	/* encode our guest_fields */
	EncodeVmcsStateFields(&guest_fields);

	if (__vmx_vmclear(&VmmState->vmcs_region_pa) != VMX_OK || 
		__vmx_vmptrld(&VmmState->vmcs_region_pa))
	{
		DEBUG_LOG("Unable to clear the vmcs region");
		return STATUS_ABANDONED;
	}

	__vmx_vmwrite(guest_fields.natural_state.cr0, __readcr0());
	__vmx_vmwrite(guest_fields.natural_state.cr3, __readcr3());
	__vmx_vmwrite(guest_fields.natural_state.cr4, __readcr4());
	__vmx_vmwrite(guest_fields.natural_state.dr7, __readdr(7));

	__vmx_vmwrite(guest_fields.natural_state.rsp, 0);
	__vmx_vmwrite(guest_fields.natural_state.rip, 0);

	__vmx_vmwrite(guest_fields.natural_state.rflags, __readeflags());

	__vmx_vmwrite(guest_fields.word_state.cs_selector, __read_cs());
	__vmx_vmwrite(guest_fields.word_state.ds_selector, __read_ds());
	__vmx_vmwrite(guest_fields.word_state.es_selector, __read_es());
	__vmx_vmwrite(guest_fields.word_state.fs_selector, __read_fs());
	__vmx_vmwrite(guest_fields.word_state.gs_selector, __read_gs());
	__vmx_vmwrite(guest_fields.word_state.ldtr_selector, __read_ldtr());
	__vmx_vmwrite(guest_fields.word_state.ss_selector, __read_ss());
	__vmx_vmwrite(guest_fields.word_state.tr_selector, __read_tr());

	__vmx_vmwrite(guest_fields.dword_state.cs_limit, __segmentlimit(__read_cs()));
	__vmx_vmwrite(guest_fields.dword_state.ds_limit, __segmentlimit(__read_ds()));
	__vmx_vmwrite(guest_fields.dword_state.es_limit, __segmentlimit(__read_es()));
	__vmx_vmwrite(guest_fields.dword_state.fs_limit, __segmentlimit(__read_fs()));
	__vmx_vmwrite(guest_fields.dword_state.gs_limit, __segmentlimit(__read_gs()));
	__vmx_vmwrite(guest_fields.dword_state.ldtr_limit, __segmentlimit(__read_ldtr()));
	__vmx_vmwrite(guest_fields.dword_state.ss_limit, __segmentlimit(__read_ss()));
	__vmx_vmwrite(guest_fields.dword_state.tr_limit, __segmentlimit(__read_tr()));
}
