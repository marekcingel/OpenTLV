// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#ifndef OPENTLV_BUILTINS_BLUETOOTH_UUID_H
#define OPENTLV_BUILTINS_BLUETOOTH_UUID_H

#include "tlv/codec/values.h"
#include "tlv/value.h"

/**
 * @file
 * @ingroup codecs
 * @brief Allocation-free Bluetooth UUID value and list codecs.
 *
 * All descriptors have static lifetime and work independently of AD Types,
 * the Bluetooth format, schema and registry. Wire UUIDs are little-endian.
 * No codec changes the source bytes or allocates. Use tlv_codec_decode() and
 * tlv_codec_encode(); their NULL, overlap, size-query and error contracts apply.
 * Supply correctly typed and aligned objects. Decode requires at least the
 * representation's sizeof; encode requires exactly its sizeof.
 * Incorrect wire lengths or object sizes return #TLV_ERR_INVALID_VALUE;
 * insufficient output capacity returns #TLV_ERR_BUFFER_TOO_SHORT.
 * UUID assignments, versions and variants are not validated or normalized.
 *
 * @see
 * https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/CSS_v14/out/en/core-supplementary-features/data-types-specification.html
 *
 * @note Requires `OPENTLV_BLUETOOTH=ON`.
 */

#ifdef __cplusplus
extern "C" {
#endif

/** @addtogroup codecs
 * @{
 */

/** @brief A 128-bit UUID in canonical most-significant-byte-first order. */
typedef struct tlv_bluetooth_uuid128 {
    /** Bytes in printed UUID order, with no punctuation; not a mixed-endian GUID. */
    uint8_t bytes[16];
} tlv_bluetooth_uuid128_t;

/** @brief Source alias of #tlv_codec_uint16_le; no separate binary symbol.
 * Requires no optional Bluetooth component. */
#define tlv_bluetooth_codec_uuid16 tlv_codec_uint16_le
/** @brief Source alias of #tlv_codec_uint32_le; no separate binary symbol.
 * Requires no optional Bluetooth component. */
#define tlv_bluetooth_codec_uuid32 tlv_codec_uint32_le
/**
 * @brief Converts exactly 16 wire bytes to/from #tlv_bluetooth_uuid128_t.
 *
 * Reverses the complete 16-byte sequence, independently of host endianness.
 */
extern TLV_API const tlv_codec_t tlv_bluetooth_codec_uuid128;

/**
 * @brief Borrowed UUID list, retaining all original bytes in wire order.
 *
 * Keep raw storage alive and immutable. Iterate indices starting at zero while
 * less than `raw.size / uuid_size` using tlv_bluetooth_uuid_list_at(). Empty lists
 * have no entries. Publicly constructed views are validated before access.
 */
typedef struct tlv_bluetooth_uuid_list {
    /** Complete borrowed wire value; NULL data is valid only for zero size. */
    tlv_value_t raw;
    /** Wire bytes per UUID: exactly 2, 4 or 16. */
    size_t uuid_size;
} tlv_bluetooth_uuid_list_t;

/**
 * @brief UUID16 list codec using #tlv_bluetooth_uuid_list_t (width 2).
 *
 * Decode borrows the input and validates its length is a multiple of the UUID
 * width, including zero. Encode validates the view and copies its raw bytes
 * exactly. A mismatched width, partial UUID or size exceeding SIZE_MAX returns
 * #TLV_ERR_INVALID_VALUE; nonempty NULL data returns
 * #TLV_ERR_NULL_ARG. No AD framing limit or completeness policy applies.
 * Use for AD Types 0x02 and 0x03; retain the AD Type separately.
 */
extern TLV_API const tlv_codec_t tlv_bluetooth_codec_uuid16_list;
/**
 * @brief UUID32 list codec (width 4), for AD Types 0x04 and 0x05.
 *
 * Same borrowing, validation and encoding contract as #tlv_bluetooth_codec_uuid16_list.
 */
extern TLV_API const tlv_codec_t tlv_bluetooth_codec_uuid32_list;
/**
 * @brief UUID128 list codec (width 16), for AD Types 0x06 and 0x07.
 *
 * Same borrowing, validation and encoding contract as #tlv_bluetooth_codec_uuid16_list.
 */
extern TLV_API const tlv_codec_t tlv_bluetooth_codec_uuid128_list;

/**
 * @brief Decodes one UUID by index without allocation or advancing state.
 *
 * @param[in] list Required borrowed view with readable, immutable raw storage.
 * @param[in] index Zero-based UUID index, strictly less than the entry count.
 * @param[out] value Required object: uint16_t, uint32_t or
 *                  #tlv_bluetooth_uuid128_t according to the list width.
 *                  Must not overlap the view or its raw storage.
 * @param[in] capacity Destination object capacity in bytes.
 * @return #TLV_OK on success.
 * @return #TLV_ERR_NULL_ARG for missing pointers, including nonempty NULL data.
 * @return #TLV_ERR_INVALID_VALUE for invalid width, partial UUID,
 *         non-native raw size or an out-of-range index (also for empty lists).
 * @return #TLV_ERR_BUFFER_TOO_SHORT for insufficient object capacity.
 * @note The view and source remain unchanged. Destination is unchanged on error.
 */
TLV_API tlv_result_t tlv_bluetooth_uuid_list_at(const tlv_bluetooth_uuid_list_t* list, size_t index,
                                                void* value, size_t capacity);

/** @} */
#ifdef __cplusplus
}
#endif
#endif /* OPENTLV_BUILTINS_BLUETOOTH_UUID_H */
