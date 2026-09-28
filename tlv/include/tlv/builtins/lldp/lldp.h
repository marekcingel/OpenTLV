#ifndef OPENTLV_BUILTINS_LLDP_LLDP_H
#define OPENTLV_BUILTINS_LLDP_LLDP_H

#include "tlv/format.h"
#include "tlv/definition.h"

/**
 * @file
 * @ingroup formats
 * @brief LLDP packed 7-bit Type and 9-bit Length framing.
 *
 * The two-octet header is big-endian: Type occupies bits 15..9 and Length
 * occupies bits 8..0. Length counts Value octets only. A canonical Tag is one
 * byte in 0..127, borrowed from immutable static storage when decoding; Value
 * borrows the input. All Types and lengths 0..511 are accepted as framing.
 *
 * Values are opaque, including organisational OUI/subtype prefixes. This
 * descriptor does not validate LLDPDU ordering, occurrences, type-specific
 * Value constraints or termination. Type 0 is exposed as an ordinary element;
 * callers select the TLV region and handle End/padding at the protocol layer.
 * There are no automatically constructed Values. No operation allocates.
 *
 * @note Requires `OPENTLV_LLDP=ON`. This is framing support, not complete
 * IEEE 802.1AB conformance or an LLDP agent.
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Immutable LLDP framing descriptor with static lifetime.
 *
 * Decode rejects incomplete headers/Values with #TLV_ERR_BUFFER_TOO_SHORT.
 * Measure/encode reject a Tag size other than one with #TLV_ERR_INVALID_TAG_SIZE,
 * a Type above 127 with #TLV_ERR_INVALID_TAG, and a Value size above 511 with
 * #TLV_ERR_INVALID_LENGTH. Source Tag/Length byte envelopes overlap; semantic
 * Tag storage uses #TLV_TAG_BINDING_FORMAT. Measurement needs no Value bytes.
 */
extern TLV_API const tlv_format_t tlv_format_lldp;

/**
 * @brief Immutable registry for base LLDP Types 0..8 and organisational Type 127.
 *
 * Names describe Type identifiers only. Reserved Types 9..126 have no entry but
 * remain representable by the framing descriptor. Lookup imposes no Schema or
 * Codec constraints. Entries and their identifier bytes have static lifetime.
 * @see tlv_definition_find
 */
extern TLV_API const tlv_definition_registry_t tlv_lldp_types;

#ifdef __cplusplus
}
#endif
#endif
