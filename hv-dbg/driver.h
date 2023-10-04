#ifndef DRIVER_H
#define DRIVER_H

#include <ntifs.h>

#define DEBUG_LOG(fmt, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "[+] " fmt "\n", ##__VA_ARGS__)
#define DEBUG_ERROR(fmt, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "[-] " fmt "\n", ##__VA_ARGS__)

#define STATIC static

#define POOL_TAG_VMM 'vmmm'

typedef struct _CPUID
{
        INT eax;
        INT ebx;
        INT ecx;
        INT edx;

} CPUID, * PCPUID;

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

#define MSR_IA32_SYSENTER_CS  0x174
#define MSR_IA32_SYSENTER_ESP 0x175
#define MSR_IA32_SYSENTER_EIP 0x176
#define MSR_IA32_DEBUGCTL     0x1D9

#define MSR_LSTAR 0xC0000082

#define MSR_FS_BASE        0xC0000100
#define MSR_GS_BASE        0xC0000101
#define MSR_SHADOW_GS_BASE 0xC0000102 // SwapGS GS shadow

#define ALIGNMENT_PAGE_SIZE 4096
#define MAXIMUM_ADDRESS     0xffffffffffffffff
#define VMCS_SIZE           4096
#define VMXON_SIZE          4096

typedef union _IA32_FEATURE_CONTROL_MSR
{
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
	UINT64 bit_address;

} IA32_FEATURE_CONTROL_MSR, * PIA32_FEATURE_CONTROL_MSR;

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

typedef union _IA32_VMX_BASIC_MSR
{
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

	UINT64 bit_address;

} IA32_VMX_BASIC_MSR, * PIA32_VMX_BASIC_MSR;

#endif