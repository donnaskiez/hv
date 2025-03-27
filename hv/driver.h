#ifndef DRIVER_H
#define DRIVER_H

#include "common.h"

NTSTATUS
HvDrvCreate(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp);

#endif