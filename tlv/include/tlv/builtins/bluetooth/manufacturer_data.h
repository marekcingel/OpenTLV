// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#ifndef OPENTLV_BUILTINS_BLUETOOTH_MANUFACTURER_DATA_H
#define OPENTLV_BUILTINS_BLUETOOTH_MANUFACTURER_DATA_H

#include "tlv/codec/codec.h"
#include "tlv/value.h"

/**
 * @file
 * @ingroup codecs
 * @brief Allocation-free Bluetooth Manufacturer Specific Data value codec.
 *
 * Independent of AD framing, schema and Company Identifier definitions.
 * Manufacturer payloads are opaque; no vendor protocol is interpreted.
 * Use tlv_codec_decode() and tlv_codec_encode(); their NULL, overlap and
 * size-query contracts apply. Input and output (including borrowed storage)
 * must not overlap. Supply correctly typed and aligned representation objects.
 * Decode requires at least sizeof(object); encode requires exactly sizeof(object).
 * Decode preserves the destination on error. Encode reports written == 0 on error.
 *
 * @note Requires `OPENTLV_BLUETOOTH=ON`.
 */
#ifdef __cplusplus
extern "C" {
#endif

/** @addtogroup codecs
 * @{
 */

/**
 * @brief Company Identifier and borrowed opaque manufacturer payload.
 *
 * Keep decoded input storage alive and immutable while either span is used.
 * Encoding uses company_id and payload; raw is informational and ignored,
 * so a caller-constructed object may leave raw empty.
 */
typedef struct tlv_bluetooth_manufacturer_data {
    /** Numeric Company Identifier decoded from the two little-endian octets. */
    uint16_t company_id;
    /** Borrowed bytes after the identifier; NULL is valid for size zero. */
    tlv_value_t payload;
    /** Complete borrowed original value, including the identifier prefix. */
    tlv_value_t raw;
} tlv_bluetooth_manufacturer_data_t;

/**
 * @brief Static-lifetime codec for AD Type 0xFF, using #tlv_bluetooth_manufacturer_data_t.
 *
 * Decode requires at least two identifier bytes; the remainder is borrowed.
 * Encode writes the identifier little-endian and copies payload unchanged.
 * Every uint16_t identifier is accepted, including identifiers absent from a
 * registry. Empty payloads are valid; no AD framing size limit applies.
 * A short identifier, incorrect encode object size, non-native payload size
 * or total size overflow returns #TLV_ERR_INVALID_VALUE. Missing required
 * pointers or nonempty NULL payload return #TLV_ERR_NULL_ARG.
 * Insufficient output capacity returns #TLV_ERR_BUFFER_TOO_SHORT.
 * Neither direction allocates or performs Company Identifier lookup.
 */
extern TLV_API const tlv_codec_t tlv_bluetooth_codec_manufacturer_data;

/** @} */
#ifdef __cplusplus
}
#endif
#endif /* OPENTLV_BUILTINS_BLUETOOTH_MANUFACTURER_DATA_H */
