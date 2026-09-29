#ifndef OPENTLV_CODEC_VALUES_H
#define OPENTLV_CODEC_VALUES_H

#include "tlv/codec/codec.h"
#include "tlv/value.h"

/**
 * @file
 * @ingroup codecs
 * @brief Allocation-free fundamental integer and byte sequence codecs.
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

/** @brief Converts exactly one byte to/from uint8_t. */
extern TLV_API const tlv_codec_t tlv_codec_uint8;
/** @brief Converts exactly two big-endian bytes to/from uint16_t. */
extern TLV_API const tlv_codec_t tlv_codec_uint16_be;
/** @brief Converts exactly four big-endian bytes to/from uint32_t. */
extern TLV_API const tlv_codec_t tlv_codec_uint32_be;
/** @brief Converts exactly two little-endian bytes to/from uint16_t. */
extern TLV_API const tlv_codec_t tlv_codec_uint16_le;
/** @brief Converts exactly four little-endian bytes to/from uint32_t. */
extern TLV_API const tlv_codec_t tlv_codec_uint32_le;
/**
 * @brief Converts minimal big-endian two's-complement bytes to/from int64_t.
 *
 * Decode accepts 1..8 bytes and rejects redundant leading 00/FF sign octets.
 * Encode emits the shortest signed representation, including one byte for zero.
 * This is value encoding only; no ASN.1 tag or universal-type policy is applied.
 * The common object-size, capacity and size-query rules above apply.
 */
extern TLV_API const tlv_codec_t tlv_codec_int64_minimal_be;

/**
 * @brief Converts arbitrary bytes to/from a borrowed #tlv_value_t.
 *
 * Empty values are accepted. Decode borrows input, which must remain alive
 * and immutable while retained. Encode copies bytes without normalization.
 * Encode, including size queries, rejects nonempty NULL data with
 * #TLV_CODEC_ERR_NULL_ARG and non-native lengths with
 * #TLV_CODEC_ERR_INVALID_VALUE. No text or identifier semantics are applied.
 */
extern TLV_API const tlv_codec_t tlv_codec_bytes;

#ifdef __cplusplus
}
#endif

#endif /* OPENTLV_CODEC_VALUES_H */
