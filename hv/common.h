#pragma once

#include <ntddk.h>
#include <wdf.h>
#include <wdm.h>

#define DEBUG_LOG(fmt, ...)   DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "[+] " fmt "\n", ##__VA_ARGS__)
#define DEBUG_ERROR(fmt, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "[-] " fmt "\n", ##__VA_ARGS__)

#define STATIC static
#define VOID   void
#define INLINE inline
#define EXTERN extern

#define VMX_OK          0 /* all ok */
#define VMX_UNSUPPORTED 1 /* VT unsupported or disabled on 1+ cores */
#define VMX_INUSE 2

//
// VMX Memory
//
#define ALIGNMENT_PAGE_SIZE 4096
#define MAXIMUM_ADDRESS     0xffffffffffffffff
#define VMCS_SIZE           4096
#define VMXON_SIZE          4096

// PIN-Based Execution
#define PIN_BASED_VM_EXECUTION_CONTROLS_EXTERNAL_INTERRUPT        0x00000001
#define PIN_BASED_VM_EXECUTION_CONTROLS_NMI_EXITING               0x00000008
#define PIN_BASED_VM_EXECUTION_CONTROLS_VIRTUAL_NMI               0x00000020
#define PIN_BASED_VM_EXECUTION_CONTROLS_ACTIVE_VMX_TIMER          0x00000040
#define PIN_BASED_VM_EXECUTION_CONTROLS_PROCESS_POSTED_INTERRUPTS 0x00000080

#define CPU_BASED_VIRTUAL_INTR_PENDING        0x00000004
#define CPU_BASED_USE_TSC_OFFSETING           0x00000008
#define CPU_BASED_HLT_EXITING                 0x00000080
#define CPU_BASED_INVLPG_EXITING              0x00000200
#define CPU_BASED_MWAIT_EXITING               0x00000400
#define CPU_BASED_RDPMC_EXITING               0x00000800
#define CPU_BASED_RDTSC_EXITING               0x00001000
#define CPU_BASED_CR3_LOAD_EXITING            0x00008000
#define CPU_BASED_CR3_STORE_EXITING           0x00010000
#define CPU_BASED_CR8_LOAD_EXITING            0x00080000
#define CPU_BASED_CR8_STORE_EXITING           0x00100000
#define CPU_BASED_TPR_SHADOW                  0x00200000
#define CPU_BASED_VIRTUAL_NMI_PENDING         0x00400000
#define CPU_BASED_MOV_DR_EXITING              0x00800000
#define CPU_BASED_UNCOND_IO_EXITING           0x01000000
#define CPU_BASED_ACTIVATE_IO_BITMAP          0x02000000
#define CPU_BASED_MONITOR_TRAP_FLAG           0x08000000
#define CPU_BASED_ACTIVATE_MSR_BITMAP         0x10000000
#define CPU_BASED_MONITOR_EXITING             0x20000000
#define CPU_BASED_PAUSE_EXITING               0x40000000
#define CPU_BASED_ACTIVATE_SECONDARY_CONTROLS 0x80000000

#define CPU_BASED_CTL2_ENABLE_EPT         0x2
#define CPU_BASED_CTL2_RDTSCP             0x8
#define CPU_BASED_CTL2_ENABLE_VPID        0x20
#define CPU_BASED_CTL2_UNRESTRICTED_GUEST 0x80
#define CPU_BASED_CTL2_ENABLE_VMFUNC      0x2000

// VM-exit Control Bits
#define VM_EXIT_IA32E_MODE       0x00000200
#define VM_EXIT_ACK_INTR_ON_EXIT 0x00008000
#define VM_EXIT_SAVE_GUEST_PAT   0x00040000
#define VM_EXIT_LOAD_HOST_PAT    0x00080000

// VM-entry Control Bits
#define VM_ENTRY_IA32E_MODE         0x00000200
#define VM_ENTRY_SMM                0x00000400
#define VM_ENTRY_DEACT_DUAL_MONITOR 0x00000800
#define VM_ENTRY_LOAD_GUEST_PAT     0x00004000

#define EXIT_REASON_EXCEPTION_NMI                0
#define EXIT_REASON_EXTERNAL_INTERRUPT           1
#define EXIT_REASON_TRIPLE_FAULT                 2
#define EXIT_REASON_INIT                         3
#define EXIT_REASON_SIPI                         4
#define EXIT_REASON_IO_SMI                       5
#define EXIT_REASON_OTHER_SMI                    6
#define EXIT_REASON_PENDING_VIRT_INTR            7
#define EXIT_REASON_PENDING_VIRT_NMI             8
#define EXIT_REASON_TASK_SWITCH                  9
#define EXIT_REASON_CPUID                        10
#define EXIT_REASON_GETSEC                       11
#define EXIT_REASON_HLT                          12
#define EXIT_REASON_INVD                         13
#define EXIT_REASON_INVLPG                       14
#define EXIT_REASON_RDPMC                        15
#define EXIT_REASON_RDTSC                        16
#define EXIT_REASON_RSM                          17
#define EXIT_REASON_VMCALL                       18
#define EXIT_REASON_VMCLEAR                      19
#define EXIT_REASON_VMLAUNCH                     20
#define EXIT_REASON_VMPTRLD                      21
#define EXIT_REASON_VMPTRST                      22
#define EXIT_REASON_VMREAD                       23
#define EXIT_REASON_VMRESUME                     24
#define EXIT_REASON_VMWRITE                      25
#define EXIT_REASON_VMXOFF                       26
#define EXIT_REASON_VMXON                        27
#define EXIT_REASON_CR_ACCESS                    28
#define EXIT_REASON_DR_ACCESS                    29
#define EXIT_REASON_IO_INSTRUCTION               30
#define EXIT_REASON_MSR_READ                     31
#define EXIT_REASON_MSR_WRITE                    32
#define EXIT_REASON_INVALID_GUEST_STATE          33
#define EXIT_REASON_MSR_LOADING                  34
#define EXIT_REASON_MWAIT_INSTRUCTION            36
#define EXIT_REASON_MONITOR_TRAP_FLAG            37
#define EXIT_REASON_MONITOR_INSTRUCTION          39
#define EXIT_REASON_PAUSE_INSTRUCTION            40
#define EXIT_REASON_MCE_DURING_VMENTRY           41
#define EXIT_REASON_TPR_BELOW_THRESHOLD          43
#define EXIT_REASON_APIC_ACCESS                  44
#define EXIT_REASON_ACCESS_GDTR_OR_IDTR          46
#define EXIT_REASON_ACCESS_LDTR_OR_TR            47
#define EXIT_REASON_EPT_VIOLATION                48
#define EXIT_REASON_EPT_MISCONFIG                49
#define EXIT_REASON_INVEPT                       50
#define EXIT_REASON_RDTSCP                       51
#define EXIT_REASON_VMX_PREEMPTION_TIMER_EXPIRED 52
#define EXIT_REASON_INVVPID                      53
#define EXIT_REASON_WBINVD                       54
#define EXIT_REASON_XSETBV                       55
#define EXIT_REASON_APIC_WRITE                   56
#define EXIT_REASON_RDRAND                       57
#define EXIT_REASON_INVPCID                      58
#define EXIT_REASON_RDSEED                       61
#define EXIT_REASON_PML_FULL                     62
#define EXIT_REASON_XSAVES                       63
#define EXIT_REASON_XRSTORS                      64
#define EXIT_REASON_PCOMMIT                      65

#define POOLTAG        0x48564653
#define VMM_STACK_SIZE 0x8000
#define RPL_MASK       3

#define POOL_TAG_VMM 'vmmm'

#define VMX_OK          0 /* all ok */
#define VMX_UNSUPPORTED 1 /* VT unsupported or disabled on 1+ cores */
#define VMX_INUSE       2

#define MSR_APIC_BASE            0x01B
#define MSR_IA32_FEATURE_CONTROL 0x03A

#define MSR_IA32_VMX_BASIC               0x480
#define MSR_IA32_VMX_PINBASED_CTLS       0x481
#define MSR_IA32_VMX_PROCBASED_CTLS      0x482
#define MSR_IA32_VMX_EXIT_CTLS           0x483
#define MSR_IA32_VMX_ENTRY_CTLS          0x484
#define MSR_IA32_VMX_MISC                0x485
#define MSR_IA32_VMX_CR0_FIXED0          0x486
#define MSR_IA32_VMX_CR0_FIXED1          0x487
#define MSR_IA32_VMX_CR4_FIXED0          0x488
#define MSR_IA32_VMX_CR4_FIXED1          0x489
#define MSR_IA32_VMX_VMCS_ENUM           0x48A
#define MSR_IA32_VMX_PROCBASED_CTLS2     0x48B
#define MSR_IA32_VMX_EPT_VPID_CAP        0x48C
#define MSR_IA32_VMX_TRUE_PINBASED_CTLS  0x48D
#define MSR_IA32_VMX_TRUE_PROCBASED_CTLS 0x48E
#define MSR_IA32_VMX_TRUE_EXIT_CTLS      0x48F
#define MSR_IA32_VMX_TRUE_ENTRY_CTLS     0x490
#define MSR_IA32_VMX_VMFUNC              0x491

#define CPU_BASED_CTL2_ENABLE_EPT                 0x2
#define CPU_BASED_CTL2_RDTSCP                     0x8
#define CPU_BASED_CTL2_ENABLE_VPID                0x20
#define CPU_BASED_CTL2_UNRESTRICTED_GUEST         0x80
#define CPU_BASED_CTL2_VIRTUAL_INTERRUPT_DELIVERY 0x200
#define CPU_BASED_CTL2_ENABLE_INVPCID             0x1000
#define CPU_BASED_CTL2_ENABLE_VMFUNC              0x2000
#define CPU_BASED_CTL2_ENABLE_XSAVE_XRSTORS       0x100000

#define MSR_IA32_SYSENTER_CS  0x174
#define MSR_IA32_SYSENTER_ESP 0x175
#define MSR_IA32_SYSENTER_EIP 0x176
#define MSR_IA32_DEBUGCTL     0x1D9

#define MSR_LSTAR 0xC0000082

#define MSR_FS_BASE        0xC0000100
#define MSR_GS_BASE        0xC0000101
#define MSR_SHADOW_GS_BASE 0xC0000102 // SwapGS GS shadow

// CPUID RCX(s) - Based on Hyper-V
#define HYPERV_CPUID_VENDOR_AND_MAX_FUNCTIONS 0x40000000
#define HYPERV_CPUID_INTERFACE                0x40000001
#define HYPERV_CPUID_VERSION                  0x40000002
#define HYPERV_CPUID_FEATURES                 0x40000003
#define HYPERV_CPUID_ENLIGHTMENT_INFO         0x40000004
#define HYPERV_CPUID_IMPLEMENT_LIMITS         0x40000005
#define HYPERV_HYPERVISOR_PRESENT_BIT         0x80000000
#define HYPERV_CPUID_MIN                      0x40000005
#define HYPERV_CPUID_MAX                      0x4000ffff

#define DPL_USER   3
#define DPL_SYSTEM 0

typedef struct _CPUID
{
        int eax;
        int ebx;
        int ecx;
        int edx;
} CPUID, *PCPUID;

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
} IA32_FEATURE_CONTROL_MSR, *PIA32_FEATURE_CONTROL_MSR;

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
} IA32_VMX_BASIC_MSR, *PIA32_VMX_BASIC_MSR;

typedef union _MSR
{
        struct
        {
                ULONG Low;
                ULONG High;
        };

        ULONG64 Content;
} MSR, *PMSR;

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

} CR4, *PCR4;

typedef struct _GUEST_CONTEXT
{
        M128A  Xmm0;
        M128A  Xmm1;
        M128A  Xmm2;
        M128A  Xmm3;
        M128A  Xmm4;
        M128A  Xmm5;
        UINT64 rax;
        UINT64 rcx;
        UINT64 rdx;
        UINT64 rbx;
        UINT64 rsp;
        UINT64 rbp;
        UINT64 rsi;
        UINT64 rdi;
        UINT64 r8;
        UINT64 r9;
        UINT64 r10;
        UINT64 r11;
        UINT64 r12;
        UINT64 r13;
        UINT64 r14;
        UINT64 r15;
        UINT32 eflags;
} GUEST_CONTEXT, *PGUEST_CONTEXT;

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
        UINT64 pending_debug_exceptions;
        UINT64 sysenter_esp;
        UINT64 sysenter_eip;

} NATURAL_STATE, *PNATURAL_STATE;

typedef struct _QWORD_BIT_STATE
{
        UINT64 vmcs_link_pointer;
        UINT64 debug_control;
        UINT64 pat;
        UINT64 efer;
        UINT64 perf_global_control;
        UINT64 pdpte0;
        UINT64 pdpte1;
        UINT64 pdpte2;
        UINT64 pdpte3;

} QWORD_BIT_STATE, *PQWORD_BIT_STATE;

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
        UINT32 interruptibility_state;
        UINT32 activity_state;
        UINT32 smbase;
        UINT32 sysenter_cs;
        UINT32 vmx_preemption_timer_value;

} DWORD_BIT_STATE, *PDWORD_BIT_STATE;

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
        UINT16 interrupt_status;
        UINT16 pml_index;

} WORD_BIT_STATE, *PWORD_BIT_STATE;

typedef struct _VMCS_GUEST_STATE_FIELDS
{
        NATURAL_STATE   natural_state;
        QWORD_BIT_STATE qword_state;
        DWORD_BIT_STATE dword_state;
        WORD_BIT_STATE  word_state;

} VMCS_GUEST_STATE_FIELDS, *PVMCS_GUEST_STATE_FIELDS;

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

} HOST_WORD_BIT_STATE, *PHOST_WORD_BIT_STATE;

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

} HOST_NATURAL_BIT_STATE, *PHOST_NATURAL_BIT_STATE;

typedef struct _HOST_QWORD_BIT_STATE
{
        UINT64 pat;
        UINT64 efer;
        UINT64 ia32_perf_global_ctrl;

} HOST_QWORD_BIT_STATE, *PHOST_QWORD_BIT_STATE;

typedef struct _HOST_DWORD_BIT_STATE
{
        UINT32 ia32_sysenter_cs;

} HOST_DWORD_BIT_STATE, *PHOST_DWORD_BIT_STATE;

typedef struct _VMCS_HOST_STATE_FIELDS
{
        HOST_WORD_BIT_STATE    word_state;
        HOST_DWORD_BIT_STATE   dword_state;
        HOST_QWORD_BIT_STATE   qword_state;
        HOST_NATURAL_BIT_STATE natural_state;

} VMCS_HOST_STATE_FIELDS, *PVMCS_HOST_STATE_FIELDS;

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

} CONTROL_QWORD_BIT_STATE, *PCONTROL_QWORD_BIT_STATE;

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

} CONTROL_WORD_BIT_STATE, *PCONTROL_WORD_BIT_STATE;

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
        CONTROL_WORD_BIT_STATE    word_state;
        CONTROL_DWORD_BIT_STATE   dword_state;
        CONTROL_QWORD_BIT_STATE   qword_state;
        CONTROL_NATURAL_BIT_STATE natural_state;

} VMCS_CONTROL_STATE_FIELDS, *PVMCS_CONTROL_STATE_FIELDS;

typedef struct _VM_EXIT_NATURAL_STATE
{
        UINT64 exit_qualification;
        UINT64 io_rcx;
        UINT64 io_rsx;
        UINT64 io_rdi;
        UINT64 io_rip;
        UINT64 guest_linear_address;

} VM_EXIT_NATURAL_STATE, *PVM_EXIT_NATURAL_STATE;

typedef struct _VM_EXIT_QWORD_STATE
{
        UINT64 guest_physical_address;

} VM_EXIT_QWORD_STATE, *PVM_EXIT_QWORD_STATE;

typedef struct _VM_EXIT_DWORD_STATE
{
        UINT32 instruction_error;
        UINT32 reason;
        UINT32 interruption_info;
        UINT32 interruption_error_code;
        UINT32 idt_vectoring_info;
        UINT32 idt_vectoring_error_code;
        UINT32 instruction_length;
        UINT32 instruction_info;

} VM_EXIT_DWORD_STATE, *PVM_EXIT_DWORD_STATE;

typedef struct _VM_EXIT_WORD_STATE
{
        UINT16 reserved;

} VM_EXIT_WORD_STATE, *PVM_EXIT_WORD_STATE;

typedef struct _VMCS_EXIT_STATE_FIELDS
{
        VM_EXIT_WORD_STATE    word_state;
        VM_EXIT_DWORD_STATE   dword_state;
        VM_EXIT_QWORD_STATE   qword_state;
        VM_EXIT_NATURAL_STATE natural_state;

} VMCS_EXIT_STATE_FIELDS, *PVMCS_EXIT_STATE_FIELDS;

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

} VMCS_ENCODING, *PVMCS_ENCODING;

typedef enum _VMCS_ACCESS_TYPE
{
        VMCS_ACCESS_FULL = 0,
        VMCS_ACCESS_HIGH = 1

} VMCS_ACCESS_TYPE;

typedef enum _VMCS_TYPE
{
        VMCS_TYPE_CONTROL          = 0,
        VMCS_TYPE_EXIT_INFORMATION = 1,
        VMCS_TYPE_GUEST_STATE      = 2,
        VMCS_TYPE_HOST_STATE       = 3

} VMCS_TYPE;

typedef enum _VMCS_WIDTH
{
        VMCS_WIDTH_16      = 0,
        VMCS_WIDTH_64      = 1,
        VMCS_WIDTH_32      = 2,
        VMCS_WIDTH_NATURAL = 3

} VMCS_WIDTH;

#define CLEAR_CR3_RESERVED_BIT(value) ((value) & ~(1ull << 63))

typedef enum _VMCALL_ID
{
        TERMINATE_VMX = 0ull,
        TEST

}VMCALL_ID;

#define VMX_HYPERCALL_TERMINATE_VMX 0ull

#define VMCS_HOST_SELECTOR_MASK 0xF8