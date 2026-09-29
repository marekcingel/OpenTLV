#ifndef OPENTLV_CODEC_DIGITS_H
#define OPENTLV_CODEC_DIGITS_H

#include "tlv/codec/codec.h"

/**
 * @file
 * @ingroup codecs
 * @brief Decimal digit strings packed high nibble first with trailing F padding.
 *
 * Unlike numeric BCD, this representation preserves leading zero digits. It
 * performs no tag lookup, decimal scaling or protocol-specific validation.
 */
#ifdef __cplusplus
extern "C" {
#endif

/** @brief Borrowed immutable constraints for a packed digit-string codec.
 * Both pairs of bounds are inclusive and must be ordered. Decode accepts any
 * trailing F nibbles, including full padding bytes. Encode uses the shortest
 * representation satisfying min_length, filling unused nibbles with F.
 * Set equal byte bounds for a fixed-width field. Storage must outlive its codec.
 */
typedef struct tlv_digits_codec_config {
    /** Minimum number of decimal digits; zero permits empty strings. */
    size_t min_digits;
    /** Maximum number of decimal digits; SIZE_MAX means unrestricted. */
    size_t max_digits;
    /** Minimum encoded byte length. */
    size_t min_length;
    /** Maximum encoded byte length. */
    size_t max_length;
} tlv_digits_codec_config_t;

/** @brief Decodes packed digits to a NUL-terminated ASCII string.
 * @param[in] context Required borrowed #tlv_digits_codec_config_t.
 * @param[in] data Value bytes; NULL only with zero size.
 * @param[in] size Number of input bytes.
 * @param[out] value Required character buffer; must not overlap input/configuration.
 * @param[in] capacity Buffer size including the terminating NUL.
 * @return #TLV_CODEC_OK, #TLV_CODEC_ERR_NULL_ARG, #TLV_CODEC_ERR_INVALID_VALUE
 *         for invalid bounds/digits/padding, or #TLV_CODEC_ERR_BUFFER_TOO_SHORT.
 * @note No allocation occurs; output is unchanged on failure.
 */
TLV_API tlv_codec_result_t tlv_digits_decode(const void* context, const uint8_t* data, size_t size,
                                             void* value, size_t capacity);

/** @brief Encodes ASCII decimal digits, retaining leading zeros.
 * @param[in] context Required borrowed #tlv_digits_codec_config_t.
 * @param[in] value Required character array (also for an empty string).
 * @param[in] size Digit count, excluding any NUL terminator.
 * @param[out] data Destination, or NULL with zero capacity for a validated size query.
 * @param[in] capacity Destination byte capacity.
 * @param[out] written Required byte count; zero on failure.
 * @return #TLV_CODEC_OK, #TLV_CODEC_ERR_NULL_ARG, #TLV_CODEC_ERR_INVALID_VALUE
 *         for invalid bounds/digits, or #TLV_CODEC_ERR_BUFFER_TOO_SHORT.
 * @note No allocation occurs; output bytes are unchanged on failure. Input,
 *       output, configuration and written must not overlap.
 */
TLV_API tlv_codec_result_t tlv_digits_encode(const void* context, const void* value, size_t size,
                                             uint8_t* data, size_t capacity, size_t* written);

/** @brief Creates a descriptor borrowing a digit-string configuration.
 * @param[in] config Borrowed immutable configuration, validated on invocation.
 * @return Allocation-free descriptor; NULL configuration fails on invocation.
 */
static inline tlv_codec_t tlv_digits_codec(const tlv_digits_codec_config_t* config) {
    tlv_codec_t result = {config, tlv_digits_decode, tlv_digits_encode};
    return result;
}

#ifdef __cplusplus
}
#endif
#endif
