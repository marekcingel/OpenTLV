// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#ifndef OPENTLV_BUILTINS_BLUETOOTH_COMPANY_IDS_H
#define OPENTLV_BUILTINS_BLUETOOTH_COMPANY_IDS_H

#include "tlv/definition.h"

/**
 * @file
 * @ingroup core
 * @brief Bluetooth Company Identifier definitions, independent of value codecs.
 *
 * @note Requires `OPENTLV_BLUETOOTH=ON`.
 */
#ifdef __cplusplus
extern "C" {
#endif

/** @addtogroup core
 * @{
 */

/**
 * @brief Immutable Company Identifier registry with static lifetime.
 *
 * Keys are exactly two identifier octets, least-significant octet first:
 * Apple 0x004C has key {0x4C, 0x00}. Use tlv_definition_find() with a borrowed
 * two-byte tag, including an isolated Manufacturer Specific Data prefix.
 * Do not use the native memory representation of a uint16_t as a key.
 * The registry only compares byte identities; it does not decode numeric values.
 *
 * Initial coverage: 0x0000 (Ericsson), 0x0006 (Microsoft), 0x004C (Apple),
 * 0x0059 (Nordic Semiconductor), 0x0075 (Samsung) and 0x00E0 (Google).
 * Names follow the Bluetooth SIG Assigned Numbers HTML table dated 2023-12-21.
 * This is a non-exhaustive snapshot, not a validity list: missing identifiers
 * remain valid and lookup returns NULL. No value validation or vendor protocol
 * interpretation occurs. Lookup never allocates and returned entries borrow
 * static storage. Requires `OPENTLV_BLUETOOTH=ON`; no value codec is invoked.
 *
 * @see
 * https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/Assigned_Numbers/out/en/index-en.html
 */
extern TLV_API const tlv_definition_registry_t tlv_bluetooth_company_ids;

/** @} */
#ifdef __cplusplus
}
#endif
#endif /* OPENTLV_BUILTINS_BLUETOOTH_COMPANY_IDS_H */
