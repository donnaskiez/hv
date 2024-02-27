#include "lock.h"

VOID
HighIrqlLockAcquire(_Inout_ PHIGH_IRQL_LOCK Lock)
{
        if (!InterlockedCompareExchange64(Lock, TRUE, FALSE))
                YieldProcessor();
}

VOID
HighIrqlLockRelease(_Inout_ PHIGH_IRQL_LOCK Lock)
{
        InterlockedExchange64(Lock, FALSE);
}

VOID
HighIrqlLockInitialise(_Out_ PHIGH_IRQL_LOCK Lock)
{
        *Lock = 0;
}