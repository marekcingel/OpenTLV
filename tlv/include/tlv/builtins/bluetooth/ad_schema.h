// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#ifndef OPENTLV_BUILTINS_BLUETOOTH_AD_SCHEMA_H
#define OPENTLV_BUILTINS_BLUETOOTH_AD_SCHEMA_H

#include "tlv/schema/schema.h"

/**
 * @file
 * @ingroup schemas
 * @brief Bluetooth Advertising Data length and occurrence constraints.
 *
 * @note Requires `OPENTLV_BLUETOOTH=ON`.
 */

#ifdef __cplusplus
extern "C" {
#endif

/** @addtogroup schemas
 * @{
 */

/**
 * @brief Immutable schema for one block of significant Advertising Data structures.
 *
 * Use with tlv_schema_validate() and tlv_format_bluetooth_ltv. Covers Flags,
 * Local Name, Tx Power, Service UUID lists, Service Data and Manufacturer
 * Specific Data. Unknown types are accepted without value constraints.
 * All entries are optional. Flags and Local Name occur at most once; shortened
 * and complete names share one limit. Complete and incomplete UUID lists share
 * one occurrence limit per UUID width. Other covered types may repeat.
 *
 * Tx Power has exactly one value byte. UUID lists have lengths divisible by
 * 2, 4 or 16, including empty lists. Service Data requires its 2-, 4- or 16-byte
 * UUID prefix; Manufacturer Specific Data requires a two-byte Company Identifier.
 * Flags accept any length, including zero; names accept 0 through 248 bytes.
 * The format enforces the 254-byte value limit independently.
 *
 * Checks only lengths and occurrences, not flag bits, UTF-8, numeric ranges,
 * identifier assignments or payload semantics. Conditional presence based on
 * connectability and relationships between advertising and scan-response blocks
 * are outside this schema. Pass only significant structures: trailing zero
 * padding is not an element and remains a framing error. Use
 * tlv_bluetooth_ad_data_validate() to obtain the significant prefix first.
 *
 * Static lifetime, allocation-free and requires `OPENTLV_BLUETOOTH=ON`.
 * The definition registry and codecs are not required.
 *
 * @see
 * https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/CSS_v12/out/en/supplement-to-the-bluetooth-core-specification/data-types-specification.html
 * @see
 * https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/Core-60/out/en/host/generic-access-profile.html
 */
extern TLV_API const tlv_structure_schema_t tlv_bluetooth_ad_schema;

/** @} */

#ifdef __cplusplus
}
#endif

#endif /* OPENTLV_BUILTINS_BLUETOOTH_AD_SCHEMA_H */
