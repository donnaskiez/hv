#include "mm.h"

#include "ia32.h"

STATIC
BOOLEAN
MmIsMtrrEnabled()
{
        IA32_MTRR_DEF_TYPE_REGISTER mtrr = {
            .AsUInt = __readmsr(IA32_MTRR_CAPABILITIES)};
        return mtrr.MtrrEnable ? TRUE : FALSE;
}

STATIC
BOOLEAN
MmIsEptAvailable()
{
        IA32_VMX_EPT_VPID_CAP_REGISTER cap = {
            .AsUInt = __readmsr(IA32_VMX_EPT_VPID_CAP)};
}

