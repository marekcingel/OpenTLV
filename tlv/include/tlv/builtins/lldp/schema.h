// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#ifndef OPENTLV_BUILTINS_LLDP_SCHEMA_H
#define OPENTLV_BUILTINS_LLDP_SCHEMA_H

#include "tlv/schema/schema.h"

/**
 * @file
 * @ingroup schemas
 * @brief LLDPDU structural rules and sequence validation above generic Reader.
 * @note Requires `OPENTLV_LLDP=ON`. Ethernet headers and padding are excluded.
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Static base TLV length and occurrence schema for an LLDPDU.
 *
 * Requires one each of Chassis ID (2..256 bytes), Port ID (2..256), and TTL
 * (2). End (0 bytes), text Types 4..6 (0..255), and Capabilities (4) may each
 * occur at most once. Management Address (9..167) and Organisational (4..511)
 * may repeat. Unknown Types are accepted. All Values remain primitive.
 *
 * Use with tlv_format_lldp. This unordered schema does not check the mandatory
 * prefix or End position; use tlv_lldp_validate() for those sequence rules.
 * Does not decode Values or enforce subtype-specific or vendor constraints.
 */
extern TLV_API const tlv_structure_schema_t tlv_lldp_schema;

/**
 * @brief Validates base lengths/occurrences, mandatory prefix and optional End.
 *
 * Applies #tlv_lldp_schema through generic Schema, then requires the first
 * three Types to be 1, 2, 3, in that order. Remaining optional Types may be
 * in any order. End is optional but, if present, must be last. Every byte
 * after End is rejected, including zero padding: supply only the TLV region.
 * Unknown Types are retained and accepted after the mandatory prefix.
 *
 * This is strict structural validation, not LLDP agent receive/discard
 * behavior. Values need their respective codecs for field-level validation.
 * No allocations, state-machine processing or generic core modifications.
 *
 * @param[in] data TLV region, borrowed during the call; NULL only for size zero.
 * @param[in] size Region size in bytes, excluding Ethernet framing and padding.
 * @param[in] max_elements Maximum element count; zero permits no elements.
 *             Use SIZE_MAX for no application-imposed count limit.
 * @param[out] diagnostic Optional first-failure diagnostic, reset on every call.
 *             Offsets are relative to data; descriptions have static lifetime.
 * @return #TLV_OK on structural success, with or without an End TLV.
 * @return #TLV_ERR_NULL_ARG for nonempty NULL input.
 * @return #TLV_ERR_SCHEMA with MISSING detail if a mandatory Type is absent.
 * @return #TLV_ERR_SCHEMA for duplicate constrained Types, wrong prefix, or
 *         content following End.
 * @return #TLV_ERR_SCHEMA with LENGTH detail for a base Type length violation.
 * @return #TLV_ERR_LIMIT when the generic element limit is exceeded.
 * @return Any framing error from generic Reader/Schema.
 * @see tlv_lldp_schema, tlv_codec_decode
 */
TLV_API tlv_result_t tlv_lldp_validate(const uint8_t* data, size_t size, size_t max_elements,
                                       tlv_schema_diagnostic_t* diagnostic);

#ifdef __cplusplus
}
#endif
#endif
