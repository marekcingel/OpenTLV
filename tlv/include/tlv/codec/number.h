#ifndef OPENTLV_CODEC_NUMBER_H
#define OPENTLV_CODEC_NUMBER_H

#include "tlv/codec/codec.h"

/**
 * @file
 * @ingroup codecs
 * @brief Configurable unsigned integer and packed-decimal Value conversion.
 */
#ifdef __cplusplus
extern "C" {
#endif

/** @brief Representation of an unsigned numeric Value, independent of its tag. */
typedef enum tlv_number_encoding {
    /** Binary integer, most-significant byte first. */
    TLV_NUMBER_BINARY_BE,
    /** Binary integer, least-significant byte first. */
    TLV_NUMBER_BINARY_LE,
    /** Packed decimal, high nibble first, zero padded on the left; no sign or F padding. */
    TLV_NUMBER_BCD
} tlv_number_encoding_t;

/**
 * @brief Borrowed declarative configuration for a uint64_t value codec.
 *
 * Binary widths are 1..8 bytes; BCD widths are 1..9 bytes. Both bounds are
 * inclusive and min_length must not exceed max_length. Decode accepts every
 * width min_length + n * length_step (n >= 0), including leading zeros; encode
 * uses the shortest fitting permitted width. BCD digits are 1..18 and bound
 * the numeric value, not the supplied byte count; binary configurations require
 * digits == 0.
 * No decimal scaling, tag semantics or domain value constraints are implied.
 * Storage must remain valid and immutable while any descriptor borrows it.
 */
typedef struct tlv_number_codec_config {
    /** Binary byte order or packed-decimal representation. */
    tlv_number_encoding_t encoding;
    /** Minimum encoded length in bytes. */
    size_t min_length;
    /** Maximum encoded length in bytes. */
    size_t max_length;
    /** Positive increment between permitted byte lengths. */
    size_t length_step;
    /** Maximum significant decimal digits for BCD; zero for binary. */
    unsigned digits;
} tlv_number_codec_config_t;

/**
 * @brief Decodes a configured number into uint64_t; usable as a codec callback.
 * @param[in] context Required immutable #tlv_number_codec_config_t.
 * @param[in] data Readable Value bytes; NULL is allowed only with zero size,
 *                 which is rejected as an invalid length. Never an enclosing TLV.
 * @param[in] size Value byte count, within the configured bounds.
 * @param[out] value Required uint64_t destination, not overlapping input/configuration.
 * @param[in] capacity Destination capacity in bytes, at least sizeof(uint64_t).
 * @return #TLV_CODEC_OK on success.
 * @return #TLV_CODEC_ERR_NULL_ARG for missing required pointers.
 * @return #TLV_CODEC_ERR_INVALID_VALUE for invalid configuration, length or digits.
 * @return #TLV_CODEC_ERR_BUFFER_TOO_SHORT for insufficient destination capacity.
 * @note No allocation occurs. Destination is unchanged on failure.
 */
TLV_API tlv_codec_result_t tlv_number_decode(const void* context, const uint8_t* data, size_t size,
                                             void* value, size_t capacity);

/**
 * @brief Encodes a configured uint64_t; usable as a codec callback.
 * @param[in] context Required immutable #tlv_number_codec_config_t.
 * @param[in] value Required readable uint64_t object.
 * @param[in] size Object size in bytes, exactly sizeof(uint64_t).
 * @param[out] data Destination, or NULL with zero capacity for a size query.
 * @param[in] capacity Destination capacity in bytes.
 * @param[out] written Required result byte count, zero on failure.
 * @return #TLV_CODEC_OK on success, including a validated size query.
 * @return #TLV_CODEC_ERR_NULL_ARG for missing required pointers.
 * @return #TLV_CODEC_ERR_INVALID_VALUE for invalid configuration/object size or a value
 *         that cannot fit the configured lengths/digit limit.
 * @return #TLV_CODEC_ERR_BUFFER_TOO_SHORT for insufficient output capacity.
 * @note No allocation occurs. Output bytes are unchanged on failure. Input,
 *       output, configuration and written must not overlap.
 */
TLV_API tlv_codec_result_t tlv_number_encode(const void* context, const void* value, size_t size,
                                             uint8_t* data, size_t capacity, size_t* written);

/**
 * @brief Creates a descriptor borrowing a numeric configuration without allocation.
 * @param[in] config Borrowed configuration; NULL is rejected when the codec is invoked.
 * @return Descriptor with the same callbacks used by statically initialized codecs.
 * @note Configuration is validated on each operation, not by this constructor.
 */
static inline tlv_codec_t tlv_number_codec(const tlv_number_codec_config_t* config) {
    tlv_codec_t result = {config, tlv_number_decode, tlv_number_encode};
    return result;
}

#ifdef __cplusplus
}
#endif
#endif
