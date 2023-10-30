#pragma once
#include <ntddk.h>
#include <wdf.h>
#include <wdm.h>

#define DEBUG_LOG(fmt, ...)   DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "[+] " fmt "\n", ##__VA_ARGS__)
#define DEBUG_ERROR(fmt, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "[-] " fmt "\n", ##__VA_ARGS__)

//
// Global variables
//
UINT64 g_StackPointerForReturning;
UINT64 g_BasePointerForReturning;

#define VMX_OK          0 /* all ok */
#define VMX_UNSUPPORTED 1 /* VT unsupported or disabled on 1+ cores */
#define VMX_INUSE 

typedef struct _VIRTUAL_MACHINE_STATE
{
        UINT64 vmxon_region_pa;
        UINT64 vmxon_region_va;   
        UINT64 vmcs_region_pa;       
        UINT64 vmcs_region_va;   
        UINT64 eptp;              
        UINT64 vmm_stack;
        UINT64 msr_bitmap_va;
        UINT64 msr_bitmap_pa;

} VIRTUAL_MACHINE_STATE, * PVIRTUAL_MACHINE_STATE;

enum __vmexit_reason_e
{
        vmexit_nmi = 0,
        vmexit_ext_int,
        vmexit_triple_fault,
        vmexit_init_signal,
        vmexit_sipi,
        vmexit_smi,
        vmexit_other_smi,
        vmexit_interrupt_window,
        vmexit_nmi_window,
        vmexit_task_switch,
        vmexit_cpuid,
        vmexit_getsec,
        vmexit_hlt,
        vmexit_invd,
        vmexit_invlpg,
        vmexit_rdpmc,
        vmexit_rdtsc,
        vmexit_rsm,
        vmexit_vmcall,
        vmexit_vmclear,
        vmexit_vmlaunch,
        vmexit_vmptrld,
        vmexit_vmptrst,
        vmexit_vmread,
        vmexit_vmresume,
        vmexit_vmwrite,
        vmexit_vmxoff,
        vmexit_vmxon,
        vmexit_control_register_access,
        vmexit_mov_dr,
        vmexit_io_instruction,
        vmexit_rdmsr,
        vmexit_wrmsr,
        vmexit_vmentry_failure_due_to_guest_state,
        vmexit_vmentry_failure_due_to_msr_loading,
        vmexit_mwait = 36,
        vmexit_monitor_trap_flag,
        vmexit_monitor = 39,
        vmexit_pause,
        vmexit_vmentry_failure_due_to_machine_check_event,
        vmexit_tpr_below_threshold = 43,
        vmexit_apic_access,
        vmexit_virtualized_eoi,
        vmexit_access_to_gdtr_or_idtr,
        vmexit_access_to_ldtr_or_tr,
        vmexit_ept_violation,
        vmexit_ept_misconfiguration,
        vmexit_invept,
        vmexit_rdtscp,
        vmexit_vmx_preemption_timer_expired,
        vmexit_invvpid,
        vmexit_wbinvd,
        vmexit_xsetbv,
        vmexit_apic_write,
        vmexit_rdrand,
        vmexit_invpcid,
        vmexit_vmfunc,
        vmexit_encls,
        vmexit_rdseed,
        vmexit_pml_full,
        vmexit_xsaves,
        vmexit_xrstors,
};

//
// Drivers
//
NTSTATUS
DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);

VOID
DrvUnload(PDRIVER_OBJECT DriverObject);

NTSTATUS
DrvCreate(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);

NTSTATUS
DrvRead(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);

NTSTATUS
DrvWrite(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);

NTSTATUS
DrvClose(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);

NTSTATUS
DrvUnsupported(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);

//
// General functions
//
VOID
PrintChars(_In_reads_(CountChars) PCHAR BufferAddress, _In_ size_t CountChars);
VOID
PrintIrpInfo(PIRP Irp);

//
// Segment registers
//
USHORT  __readcs(VOID);
USHORT  __readds(VOID);
USHORT  __reades(VOID);
USHORT  __readss(VOID);
USHORT  __readfs(VOID);
USHORT  __readgs(VOID);
USHORT  __readldtr(VOID);
USHORT  __readtr(VOID);
USHORT  __getidtlimit(VOID);
USHORT  __getgdtlimit(VOID);
ULONG64 __readrflags(VOID);

typedef struct _CPUID
{
        int eax;
        int ebx;
        int ecx;
        int edx;
} CPUID, * PCPUID;

//
// Structures
//
typedef union _IA32_FEATURE_CONTROL_MSR
{
        ULONG64 bit_address;
        struct
        {
                ULONG64 Lock : 1;               // [0]
                ULONG64 EnableSMX : 1;          // [1]
                ULONG64 EnableVmxon : 1;        // [2]
                ULONG64 Reserved2 : 5;          // [3-7]
                ULONG64 EnableLocalSENTER : 7;  // [8-14]
                ULONG64 EnableGlobalSENTER : 1; // [15]
                ULONG64 Reserved3a : 16;        //
                ULONG64 Reserved3b : 32;        // [16-63]
        } bits;
} IA32_FEATURE_CONTROL_MSR, * PIA32_FEATURE_CONTROL_MSR;

typedef union _IA32_VMX_BASIC_MSR
{
        ULONG64 bit_address;
        struct
        {
                ULONG32 RevisionIdentifier : 31;  // [0-30]
                ULONG32 Reserved1 : 1;            // [31]
                ULONG32 RegionSize : 12;          // [32-43]
                ULONG32 RegionClear : 1;          // [44]
                ULONG32 Reserved2 : 3;            // [45-47]
                ULONG32 SupportedIA64 : 1;        // [48]
                ULONG32 SupportedDualMoniter : 1; // [49]
                ULONG32 MemoryType : 4;           // [50-53]
                ULONG32 VmExitReport : 1;         // [54]
                ULONG32 VmxCapabilityHint : 1;    // [55]
                ULONG32 Reserved3 : 8;            // [56-63]
        } bits;
} IA32_VMX_BASIC_MSR, * PIA32_VMX_BASIC_MSR;

typedef union _MSR
{
        struct
        {
                ULONG Low;
                ULONG High;
        };

        ULONG64 Content;
} MSR, * PMSR;

typedef union SEGMENT_ATTRIBUTES
{
        USHORT UCHARs;
        struct
        {
                USHORT TYPE : 4; /* 0;  Bit 40-43 */
                USHORT S : 1;    /* 4;  Bit 44 */
                USHORT DPL : 2;  /* 5;  Bit 45-46 */
                USHORT P : 1;    /* 7;  Bit 47 */

                USHORT AVL : 1; /* 8;  Bit 52 */
                USHORT L : 1;   /* 9;  Bit 53 */
                USHORT DB : 1;  /* 10; Bit 54 */
                USHORT G : 1;   /* 11; Bit 55 */
                USHORT GAP : 4;

        } Fields;
} SEGMENT_ATTRIBUTES;

typedef union _CR4
{
        struct
        {
                UINT64 vme : 1;
                UINT64 pvi : 1;
                UINT64 tsd : 1;
                UINT64 de : 1;
                UINT64 pse : 1;
                UINT64 pae : 1;
                UINT64 mce : 1;
                UINT64 pge : 1;
                UINT64 pce : 1;
                UINT64 osfxsr : 1;
                UINT64 osxmmexcpt : 1;
                UINT64 umip : 1;
                UINT64 la57 : 1;
                UINT64 vmxe : 1;
                UINT64 smxe : 1;
                UINT64 reserved_1 : 1;
                UINT64 fsgsbase : 1;
                UINT64 pcide : 1;
                UINT64 osxsave : 1;
                UINT64 kl : 1;
                UINT64 smep : 1;
                UINT64 smap : 1;
                UINT64 pke : 1;
                UINT64 cet : 1;
                UINT64 pks : 1;
                UINT64 uintr : 1;
                UINT64 reserved_2 : 37;

        } bits;

        UINT64 bit_address;

} CR4, * PCR4;

typedef struct SEGMENT_SELECTOR
{
        USHORT             SEL;
        SEGMENT_ATTRIBUTES ATTRIBUTES;
        ULONG32            LIMIT;
        ULONG64            BASE;
} SEGMENT_SELECTOR, * PSEGMENT_SELECTOR;

typedef struct _SEGMENT_DESCRIPTOR
{
        USHORT LIMIT0;
        USHORT BASE0;
        UCHAR  BASE1;
        UCHAR  ATTR0;
        UCHAR  LIMIT1ATTR1;
        UCHAR  BASE2;
} SEGMENT_DESCRIPTOR, * PSEGMENT_DESCRIPTOR;

enum SEGREGS
{
        ES = 0,
        CS,
        SS,
        DS,
        FS,
        GS,
        LDTR,
        TR
};

typedef struct _GUEST_REGS
{
        ULONG64 rax; // 0x00         // NOT VALID FOR SVM
        ULONG64 rcx;
        ULONG64 rdx; // 0x10
        ULONG64 rbx;
        ULONG64 rsp; // 0x20         // rsp is not stored here on SVM
        ULONG64 rbp;
        ULONG64 rsi; // 0x30
        ULONG64 rdi;
        ULONG64 r8; // 0x40
        ULONG64 r9;
        ULONG64 r10; // 0x50
        ULONG64 r11;
        ULONG64 r12; // 0x60
        ULONG64 r13;
        ULONG64 r14; // 0x70
        ULONG64 r15;
} GUEST_REGS, * PGUEST_REGS;

typedef union _RFLAGS
{
        struct
        {
                unsigned Reserved1 : 10;
                unsigned ID : 1;  // Identification flag
                unsigned VIP : 1; // Virtual interrupt pending
                unsigned VIF : 1; // Virtual interrupt flag
                unsigned AC : 1;  // Alignment check
                unsigned VM : 1;  // Virtual 8086 mode
                unsigned RF : 1;  // Resume flag
                unsigned Reserved2 : 1;
                unsigned NT : 1;   // Nested task flag
                unsigned IOPL : 2; // I/O privilege level
                unsigned OF : 1;
                unsigned DF : 1;
                unsigned IF : 1; // Interrupt flag
                unsigned TF : 1; // Task flag
                unsigned SF : 1; // Sign flag
                unsigned ZF : 1; // Zero flag
                unsigned Reserved3 : 1;
                unsigned AF : 1; // Borrow flag
                unsigned Reserved4 : 1;
                unsigned PF : 1; // Parity flag
                unsigned Reserved5 : 1;
                unsigned CF : 1; // Carry flag [Bit 0]
                unsigned Reserved6 : 32;
        };

        ULONG64 Content;
} RFLAGS;

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

} NATURAL_STATE, * PNATURAL_STATE;

typedef struct _QWORD_BIT_STATE
{
        UINT64 vmcs_link_pointer;
        UINT64 debug_control;
        UINT64 pat;
        UINT64 efer;
        UINT64 perf_global_control;
        UINT64 bndcfgs;

} QWORD_BIT_STATE, * PQWORD_BIT_STATE;

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

} DWORD_BIT_STATE, * PDWORD_BIT_STATE;

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

} WORD_BIT_STATE, * PWORD_BIT_STATE;

typedef struct _VMCS_GUEST_STATE_FIELDS
{
        NATURAL_STATE   natural_state;
        QWORD_BIT_STATE qword_state;
        DWORD_BIT_STATE dword_state;
        WORD_BIT_STATE  word_state;

} VMCS_GUEST_STATE_FIELDS, * PVMCS_GUEST_STATE_FIELDS;

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

} HOST_WORD_BIT_STATE, * PHOST_WORD_BIT_STATE;

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

} HOST_NATURAL_BIT_STATE, * PHOST_NATURAL_BIT_STATE;

typedef struct _HOST_DWORD_BIT_STATE
{
        UINT32 ia32_sysenter_cs;

} HOST_DWORD_BIT_STATE, * PHOST_DWORD_BIT_STATE;

typedef struct _VMCS_HOST_STATE_FIELDS
{
        HOST_WORD_BIT_STATE    word_state;
        HOST_DWORD_BIT_STATE   dword_state;
        HOST_NATURAL_BIT_STATE natural_state;

} VMCS_HOST_STATE_FIELDS, * PVMCS_HOST_STATE_FIELDS;

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

} CONTROL_DWORD_BIT_STATE, * PCONTROL_DWORD_BIT_STATE;

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

} CONTROL_NATURAL_BIT_STATE, * PCONTROL_NATURAL_BIT_STATE;

typedef struct _VMCS_CONTROL_STATE_FIELDS
{
        CONTROL_WORD_BIT_STATE    word_state;
        CONTROL_DWORD_BIT_STATE   dword_state;
        CONTROL_QWORD_BIT_STATE   qword_state;
        CONTROL_NATURAL_BIT_STATE natural_state;

} VMCS_CONTROL_STATE_FIELDS, * PVMCS_CONTROL_STATE_FIELDS;

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
        } bits;

        UINT32 address;

} VMCS_ENCODING, * PVMCS_ENCODING;

typedef enum _VMCS_ACCESS_TYPE
{
        VMCS_ACCESS_FULL = 0,
        VMCS_ACCESS_HIGH = 1

} VMCS_ACCESS_TYPE;

typedef enum _VMCS_TYPE
{
        VMCS_TYPE_CONTROL = 0,
        VMCS_TYPE_EXIT_INFORMATION = 1,
        VMCS_TYPE_GUEST_STATE = 2,
        VMCS_TYPE_HOST_STATE = 3

} VMCS_TYPE;

typedef enum _VMCS_WIDTH
{
        VMCS_WIDTH_16 = 0,
        VMCS_WIDTH_64 = 1,
        VMCS_WIDTH_32 = 2,
        VMCS_WIDTH_NATURAL = 3

} VMCS_WIDTH;