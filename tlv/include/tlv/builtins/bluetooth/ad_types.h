// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#ifndef OPENTLV_BUILTINS_BLUETOOTH_AD_TYPES_H
#define OPENTLV_BUILTINS_BLUETOOTH_AD_TYPES_H

#include "tlv/definition.h"

/**
 * @file
 * @ingroup core
 * @brief Bluetooth Advertising Data Type definitions.
 *
 * @note Requires `OPENTLV_BLUETOOTH=ON`.
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Immutable Bluetooth Advertising Data Type registry with static lifetime.
 *
 * Maps canonical one-byte identifiers to Bluetooth SIG Assigned Numbers names.
 * Initial coverage is 0x01-0x0A, 0x16, 0x20, 0x21 and 0xFF. This is not an
 * exhaustive list of assigned types. Unknown types remain valid for structural
 * parsing; lookup does not validate values or impose schema constraints.
 *
 * Use tlv_definition_find() for allocation-free lookup. Requires
 * `OPENTLV_BLUETOOTH=ON`; no parser or writer is required.
 *
 * @see https://www.bluetooth.com/specifications/assigned-numbers/
 */
extern TLV_API const tlv_definition_registry_t tlv_bluetooth_ad_types;

#ifdef __cplusplus
}
#endif

#endif /* OPENTLV_BUILTINS_BLUETOOTH_AD_TYPES_H */
