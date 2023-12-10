#ifndef ENCODE_H
#define ENCODE_H

#include "common.h"

VOID
EncodeVmcsGuestStateFields(
        _Out_ PVMCS_GUEST_STATE_FIELDS Fields);

VOID
EncodeVmcsControlStateFields(
        _Out_ PVMCS_CONTROL_STATE_FIELDS Fields);

VOID
EncodeVmcsHostStateFields(
        _Out_ PVMCS_HOST_STATE_FIELDS Fields);

VOID
EncodeVmcsExitStateFields(
        _Out_ PVMCS_EXIT_STATE_FIELDS Fields
);

#endif 