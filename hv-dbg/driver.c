#include "driver.h"

UNICODE_STRING device_name = RTL_CONSTANT_STRING(L"hv-dbg");
UNICODE_STRING device_link = RTL_CONSTANT_STRING(L"hv-dbg-link");



STATIC
BOOLEAN
hvdbgIsVmxSupported()
{
//Here we check for vmx support by checking the CPUID.1:ECX.VMX[bit 5]
//https://en.wikipedia.org/wiki/CPUID#EAX=1:_Processor_Info_and_Feature_Bits
//source: 3c 23.6

    CPUID cpuid = { 0 };
	IA32_FEATURE_CONTROL_MSR control_msr = { 0 };

    __cpuid((INT*)&cpuid, 1);

	if ((cpuid.ecx & (1 << 5)) == FALSE)
		return FALSE;

    //Here we enable the use of VMXON inside and outside of SMX
    //Bit 0 is the lockbit, if its set to 0 VMXON will cause an exception
    //Bit 2 enables VMXON outside of SMX operation
    //source: 3c 23.7

    control_msr.All = __readmsr(MSR_IA32_FEATURE_CONTROL);

    if (control_msr.bits.Lock == FALSE)
    {
        control_msr.bits.Lock = TRUE;
        control_msr.bits.EnableVmxon = TRUE;

        __writemsr(MSR_IA32_FEATURE_CONTROL, control_msr.All);
    }
    else if (control_msr.bits.EnableVmxon == FALSE)
    {
        DEBUG_LOG("VMX locked off in BIOS");
        return FALSE;
    }

    return TRUE;
}

NTSTATUS 
DriverEntry(
	PDRIVER_OBJECT DriverObject,
	PUNICODE_STRING RegistryPath
)
{
	UNREFERENCED_PARAMETER(RegistryPath);

	NTSTATUS status = STATUS_SUCCESS;

	status = IoCreateDevice(
		DriverObject,
		0,
		&device_name,
		FILE_DEVICE_UNKNOWN,
		FILE_DEVICE_SECURE_OPEN,
		FALSE,
		&DriverObject->DeviceObject
	);

	if (!NT_SUCCESS(status))
		return STATUS_FAILED_DRIVER_ENTRY;

	status = IoCreateSymbolicLink(
		&device_link,
		&device_name
	);

	if (!NT_SUCCESS(status))
	{
		IoDeleteDevice(&DriverObject->DeviceObject);
		return STATUS_FAILED_DRIVER_ENTRY;
	}

	DEBUG_LOG("Driver entry complete");

	return status;
}