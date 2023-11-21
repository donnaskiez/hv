#ifndef ENCODE_H
#define ENCODE_H

#include "common.h"

VOID
EncodeVmcsGuestStateFields(
        _Out_ PVMCS_GUEST_STATE_FIELDS Fields);

VOID
EncodeVmcsControlStateFields(
        _In_ PVMCS_CONTROL_STATE_FIELDS Fields);

VOID
EncodeVmcsHostStateFields(
        _Out_ PVMCS_HOST_STATE_FIELDS Fields);

#endif 