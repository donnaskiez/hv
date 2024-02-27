#ifndef LOCK_H
#define LOCK_H

#include "common.h"

/* Object that represents a lock to be used at irql >= DISPATCH_LEVEL */
typedef ULONG_PTR HIGH_IRQL_LOCK, *PHIGH_IRQL_LOCK;

/*
 * Its assumed that when these functions are called, the irql >= DISPATCH_LEVEL. This means there is
 * no need for us to save the IRQL value and restore the previous IRQL value similar to how
 * KeAcquireSpinLock and the release function work.
 */

VOID
HighIrqlLockAcquire(_Inout_ PHIGH_IRQL_LOCK Lock);

VOID
HighIrqlLockRelease(_Inout_ PHIGH_IRQL_LOCK Lock);

VOID
HighIrqlLockInitialise(_Out_ PHIGH_IRQL_LOCK Lock);

#endif