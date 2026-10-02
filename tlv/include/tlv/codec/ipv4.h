// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#ifndef OPENTLV_CODEC_IPV4_H
#define OPENTLV_CODEC_IPV4_H

#include "tlv/codec/codec.h"
#include "tlv/value.h"

/**
 * @file
 * @ingroup codecs
 * @brief Allocation-free IPv4 address and address list codecs.
 *
 * Descriptors have static lifetime and require no optional protocol component.
 * Use tlv_codec_decode() and tlv_codec_encode(); their pointer, overlap and
 * error contracts apply. Decode requires at least sizeof the documented C
 * representation; encode requires exactly sizeof that representation.
 * Wrong wire lengths or object sizes return #TLV_CODEC_ERR_INVALID_VALUE;
 * insufficient destination capacity returns #TLV_CODEC_ERR_BUFFER_TOO_SHORT.
 * Encode size queries validate the representation before reporting its size.
 * No codec applies option-specific limits or allocates storage.
 */

#ifdef __cplusplus
extern "C" {
#endif

/** @brief IPv4 address in network octet order, independent of host endianness. */
typedef struct tlv_ipv4 {
    /** Four address octets, in the order used in dotted-decimal notation. */
    uint8_t bytes[4];
} tlv_ipv4_t;

/** @brief Converts exactly four bytes to/from #tlv_ipv4_t without address policy checks. */
extern TLV_API const tlv_codec_t tlv_codec_ipv4;

/** @brief Borrowed sequence of IPv4 addresses in network octet order. */
typedef struct tlv_ipv4_list {
    /** Borrowed bytes; size must be divisible by four, including zero.
     * Keep storage alive and immutable while the list is retained. */
    tlv_value_t raw;
} tlv_ipv4_list_t;

/**
 * @brief Converts a multiple of four bytes to/from #tlv_ipv4_list_t.
 *
 * Decode borrows input. Encode validates the view and copies all raw bytes,
 * preserving address order and duplicates. Empty lists are valid. Nonempty
 * NULL data returns #TLV_CODEC_ERR_NULL_ARG; non-native lengths or incomplete
 * addresses return #TLV_CODEC_ERR_INVALID_VALUE, including for size queries.
 */
extern TLV_API const tlv_codec_t tlv_codec_ipv4_list;

/**
 * @brief Copies one address from a validated borrowed IPv4 list.
 *
 * @param[in] list Required view with readable, immutable raw storage.
 * @param[in] index Zero-based index, less than raw.size / 4.
 * @param[out] value Required destination, not overlapping the view or its bytes.
 * @return #TLV_CODEC_OK on success.
 * @return #TLV_CODEC_ERR_NULL_ARG for missing pointers or nonempty NULL data.
 * @return #TLV_CODEC_ERR_INVALID_VALUE for malformed lengths or an invalid index.
 * @note The destination is unchanged on failure. No allocation occurs.
 */
TLV_API tlv_codec_result_t tlv_ipv4_list_at(const tlv_ipv4_list_t* list, size_t index,
                                            tlv_ipv4_t* value);

#ifdef __cplusplus
}
#endif

#endif /* OPENTLV_CODEC_IPV4_H */
