#pragma once
#include <ntddk.h>
#include <wdf.h>
#include <wdm.h>

#define DEBUG_LOG(fmt, ...)   DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "[+] " fmt "\n", ##__VA_ARGS__)
#define DEBUG_ERROR(fmt, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "[-] " fmt "\n", ##__VA_ARGS__)

#define STATIC static
#define VOID void

extern USHORT  __readcs(VOID);
extern USHORT  __readds(VOID);
extern USHORT  __reades(VOID);
extern USHORT  __readss(VOID);
extern USHORT  __readfs(VOID);
extern USHORT  __readgs(VOID);
extern USHORT  __readldtr(VOID);
extern USHORT  __readtr(VOID);
extern USHORT  __getidtlimit(VOID);
extern USHORT  __getgdtlimit(VOID);
extern ULONG64 __readrflags(VOID);

#define VMX_OK          0 /* all ok */
#define VMX_UNSUPPORTED 1 /* VT unsupported or disabled on 1+ cores */
#define VMX_INUSE 

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

enum VMCS_FIELDS
{
        GUEST_ES_SELECTOR = 0x00000800,
        GUEST_CS_SELECTOR = 0x00000802,
        GUEST_SS_SELECTOR = 0x00000804,
        GUEST_DS_SELECTOR = 0x00000806,
        GUEST_FS_SELECTOR = 0x00000808,
        GUEST_GS_SELECTOR = 0x0000080a,
        GUEST_LDTR_SELECTOR = 0x0000080c,
        GUEST_TR_SELECTOR = 0x0000080e,
        HOST_ES_SELECTOR = 0x00000c00,
        HOST_CS_SELECTOR = 0x00000c02,
        HOST_SS_SELECTOR = 0x00000c04,
        HOST_DS_SELECTOR = 0x00000c06,
        HOST_FS_SELECTOR = 0x00000c08,
        HOST_GS_SELECTOR = 0x00000c0a,
        HOST_TR_SELECTOR = 0x00000c0c,
        IO_BITMAP_A = 0x00002000,
        IO_BITMAP_A_HIGH = 0x00002001,
        IO_BITMAP_B = 0x00002002,
        IO_BITMAP_B_HIGH = 0x00002003,
        MSR_BITMAP = 0x00002004,
        MSR_BITMAP_HIGH = 0x00002005,
        VM_EXIT_MSR_STORE_ADDR = 0x00002006,
        VM_EXIT_MSR_STORE_ADDR_HIGH = 0x00002007,
        VM_EXIT_MSR_LOAD_ADDR = 0x00002008,
        VM_EXIT_MSR_LOAD_ADDR_HIGH = 0x00002009,
        VM_ENTRY_MSR_LOAD_ADDR = 0x0000200a,
        VM_ENTRY_MSR_LOAD_ADDR_HIGH = 0x0000200b,
        TSC_OFFSET = 0x00002010,
        TSC_OFFSET_HIGH = 0x00002011,
        VIRTUAL_APIC_PAGE_ADDR = 0x00002012,
        VIRTUAL_APIC_PAGE_ADDR_HIGH = 0x00002013,
        VMFUNC_CONTROLS = 0x00002018,
        VMFUNC_CONTROLS_HIGH = 0x00002019,
        EPT_POINTER = 0x0000201A,
        EPT_POINTER_HIGH = 0x0000201B,
        EPTP_LIST = 0x00002024,
        EPTP_LIST_HIGH = 0x00002025,
        GUEST_PHYSICAL_ADDRESS = 0x2400,
        GUEST_PHYSICAL_ADDRESS_HIGH = 0x2401,
        VMCS_LINK_POINTER = 0x00002800,
        VMCS_LINK_POINTER_HIGH = 0x00002801,
        GUEST_IA32_DEBUGCTL = 0x00002802,
        GUEST_IA32_DEBUGCTL_HIGH = 0x00002803,
        PIN_BASED_VM_EXEC_CONTROL = 0x00004000,
        CPU_BASED_VM_EXEC_CONTROL = 0x00004002,
        EXCEPTION_BITMAP = 0x00004004,
        PAGE_FAULT_ERROR_CODE_MASK = 0x00004006,
        PAGE_FAULT_ERROR_CODE_MATCH = 0x00004008,
        CR3_TARGET_COUNT = 0x0000400a,
        VM_EXIT_CONTROLS = 0x0000400c,
        VM_EXIT_MSR_STORE_COUNT = 0x0000400e,
        VM_EXIT_MSR_LOAD_COUNT = 0x00004010,
        VM_ENTRY_CONTROLS = 0x00004012,
        VM_ENTRY_MSR_LOAD_COUNT = 0x00004014,
        VM_ENTRY_INTR_INFO_FIELD = 0x00004016,
        VM_ENTRY_EXCEPTION_ERROR_CODE = 0x00004018,
        VM_ENTRY_INSTRUCTION_LEN = 0x0000401a,
        TPR_THRESHOLD = 0x0000401c,
        SECONDARY_VM_EXEC_CONTROL = 0x0000401e,
        VM_INSTRUCTION_ERROR = 0x00004400,
        VM_EXIT_REASON = 0x00004402,
        VM_EXIT_INTR_INFO = 0x00004404,
        VM_EXIT_INTR_ERROR_CODE = 0x00004406,
        IDT_VECTORING_INFO_FIELD = 0x00004408,
        IDT_VECTORING_ERROR_CODE = 0x0000440a,
        VM_EXIT_INSTRUCTION_LEN = 0x0000440c,
        VMX_INSTRUCTION_INFO = 0x0000440e,
        GUEST_ES_LIMIT = 0x00004800,
        GUEST_CS_LIMIT = 0x00004802,
        GUEST_SS_LIMIT = 0x00004804,
        GUEST_DS_LIMIT = 0x00004806,
        GUEST_FS_LIMIT = 0x00004808,
        GUEST_GS_LIMIT = 0x0000480a,
        GUEST_LDTR_LIMIT = 0x0000480c,
        GUEST_TR_LIMIT = 0x0000480e,
        GUEST_GDTR_LIMIT = 0x00004810,
        GUEST_IDTR_LIMIT = 0x00004812,
        GUEST_ES_AR_BYTES = 0x00004814,
        GUEST_CS_AR_BYTES = 0x00004816,
        GUEST_SS_AR_BYTES = 0x00004818,
        GUEST_DS_AR_BYTES = 0x0000481a,
        GUEST_FS_AR_BYTES = 0x0000481c,
        GUEST_GS_AR_BYTES = 0x0000481e,
        GUEST_LDTR_AR_BYTES = 0x00004820,
        GUEST_TR_AR_BYTES = 0x00004822,
        GUEST_INTERRUPTIBILITY_INFO = 0x00004824,
        GUEST_ACTIVITY_STATE = 0x00004826,
        GUEST_SM_BASE = 0x00004828,
        GUEST_SYSENTER_CS = 0x0000482A,
        HOST_IA32_SYSENTER_CS = 0x00004c00,
        CR0_GUEST_HOST_MASK = 0x00006000,
        CR4_GUEST_HOST_MASK = 0x00006002,
        CR0_READ_SHADOW = 0x00006004,
        CR4_READ_SHADOW = 0x00006006,
        CR3_TARGET_VALUE0 = 0x00006008,
        CR3_TARGET_VALUE1 = 0x0000600a,
        CR3_TARGET_VALUE2 = 0x0000600c,
        CR3_TARGET_VALUE3 = 0x0000600e,
        EXIT_QUALIFICATION = 0x00006400,
        GUEST_LINEAR_ADDRESS = 0x0000640a,
        GUEST_CR0 = 0x00006800,
        GUEST_CR3 = 0x00006802,
        GUEST_CR4 = 0x00006804,
        GUEST_ES_BASE = 0x00006806,
        GUEST_CS_BASE = 0x00006808,
        GUEST_SS_BASE = 0x0000680a,
        GUEST_DS_BASE = 0x0000680c,
        GUEST_FS_BASE = 0x0000680e,
        GUEST_GS_BASE = 0x00006810,
        GUEST_LDTR_BASE = 0x00006812,
        GUEST_TR_BASE = 0x00006814,
        GUEST_GDTR_BASE = 0x00006816,
        GUEST_IDTR_BASE = 0x00006818,
        GUEST_DR7 = 0x0000681a,
        GUEST_RSP = 0x0000681c,
        GUEST_RIP = 0x0000681e,
        GUEST_RFLAGS = 0x00006820,
        GUEST_PENDING_DBG_EXCEPTIONS = 0x00006822,
        GUEST_SYSENTER_ESP = 0x00006824,
        GUEST_SYSENTER_EIP = 0x00006826,
        HOST_CR0 = 0x00006c00,
        HOST_CR3 = 0x00006c02,
        HOST_CR4 = 0x00006c04,
        HOST_FS_BASE = 0x00006c06,
        HOST_GS_BASE = 0x00006c08,
        HOST_TR_BASE = 0x00006c0a,
        HOST_GDTR_BASE = 0x00006c0c,
        HOST_IDTR_BASE = 0x00006c0e,
        HOST_IA32_SYSENTER_ESP = 0x00006c10,
        HOST_IA32_SYSENTER_EIP = 0x00006c12,
        HOST_RSP = 0x00006c14,
        HOST_RIP = 0x00006c16,
};

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

#define VMX_OK                  0 /* all ok */
#define VMX_UNSUPPORTED 1 /* VT unsupported or disabled on 1+ cores */
#define VMX_INUSE 2

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

#define CPU_BASED_CTL2_ENABLE_EPT						0x2
#define CPU_BASED_CTL2_RDTSCP							0x8
#define CPU_BASED_CTL2_ENABLE_VPID						0x20
#define CPU_BASED_CTL2_UNRESTRICTED_GUEST				0x80
#define CPU_BASED_CTL2_VIRTUAL_INTERRUPT_DELIVERY		0x200
#define CPU_BASED_CTL2_ENABLE_INVPCID					0x1000
#define CPU_BASED_CTL2_ENABLE_VMFUNC					0x2000
#define CPU_BASED_CTL2_ENABLE_XSAVE_XRSTORS				0x100000

#define MSR_IA32_SYSENTER_CS  0x174
#define MSR_IA32_SYSENTER_ESP 0x175
#define MSR_IA32_SYSENTER_EIP 0x176
#define MSR_IA32_DEBUGCTL     0x1D9

#define MSR_LSTAR 0xC0000082

#define MSR_FS_BASE        0xC0000100
#define MSR_GS_BASE        0xC0000101
#define MSR_SHADOW_GS_BASE 0xC0000102 // SwapGS GS shadow

// CPUID RCX(s) - Based on Hyper-V
#define HYPERV_CPUID_VENDOR_AND_MAX_FUNCTIONS   0x40000000
#define HYPERV_CPUID_INTERFACE                  0x40000001
#define HYPERV_CPUID_VERSION                    0x40000002
#define HYPERV_CPUID_FEATURES                   0x40000003
#define HYPERV_CPUID_ENLIGHTMENT_INFO           0x40000004
#define HYPERV_CPUID_IMPLEMENT_LIMITS           0x40000005
#define HYPERV_HYPERVISOR_PRESENT_BIT           0x80000000
#define HYPERV_CPUID_MIN                        0x40000005
#define HYPERV_CPUID_MAX                        0x4000ffff

#define DPL_USER   3
#define DPL_SYSTEM 0

// Exit Qualifications for MOV for Control Register Access
#define TYPE_MOV_TO_CR   0
#define TYPE_MOV_FROM_CR 1
#define TYPE_CLTS        2
#define TYPE_LMSW        3

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
        M128A Xmm0;
        M128A Xmm1;
        M128A Xmm2;
        M128A Xmm3;
        M128A Xmm4;
        M128A Xmm5;
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

typedef union _MOV_CR_QUALIFICATION
{
        ULONG_PTR All;
        struct
        {
                ULONG ControlRegister : 4;
                ULONG AccessType : 2;
                ULONG LMSWOperandType : 1;
                ULONG Reserved1 : 1;
                ULONG Register : 4;
                ULONG Reserved2 : 4;
                ULONG LMSWSourceData : 16;
                ULONG Reserved3;
        } Fields;
} MOV_CR_QUALIFICATION, * PMOV_CR_QUALIFICATION;