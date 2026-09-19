#ifndef OPENTLV_CODEC_H
#define OPENTLV_CODEC_H

#include "tlv/export.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file codec.h
 * @brief Value codec descriptors for converting raw TLV values to and from C representations.
 */

/**
 * @brief Result code of a value conversion.
 *
 * Value-conversion errors are independent of TLV framing errors, which use
 * #tlv_result_t.
 *
 * @see tlv_codec_strerror
 */
typedef enum tlv_codec_result {
    /** The conversion succeeded. */
    TLV_CODEC_OK = 0,
    /** A required pointer argument is `NULL`. */
    TLV_CODEC_ERR_NULL_ARG,
    /** A supplied buffer is too small for the data or representation. */
    TLV_CODEC_ERR_BUFFER_TOO_SHORT,
    /** The value or its representation is invalid for the codec. */
    TLV_CODEC_ERR_INVALID_VALUE,
    /** The requested direction or operation is not supported by the codec. */
    TLV_CODEC_ERR_UNSUPPORTED,
    /** A complete structure is malformed, or violates its schema or limits. */
    TLV_CODEC_ERR_INVALID_STRUCTURE
} tlv_codec_result_t;

/**
 * @brief Borrowed codec descriptor with an optional immutable context.
 *
 * A descriptor neither allocates nor takes ownership of anything. Each codec
 * documents its C representation and required alignment; callers supply
 * correctly typed and aligned objects. Capacities and sizes are in bytes.
 * Callbacks must respect bounds and must not require heap allocation.
 *
 * - **Decode** consumes the entire raw value and may return a representation
 *   that borrows the input bytes; that input must then outlive the
 *   representation.
 * - **Encode** with `data == NULL` and `capacity == 0` validates the value and
 *   reports its exact encoded size without writing. A normal success reports
 *   the bytes written.
 * - A callback may be `NULL` for an unsupported direction. Errors propagate
 *   unchanged.
 * - On error, destination contents are unspecified, and the tlv_codec_encode()
 *   wrapper reports `written == 0`.
 * - Input and output must not overlap unless the codec explicitly supports it.
 *
 * @see tlv_codec_decode, tlv_codec_encode
 */
typedef struct tlv_codec {
    /** Immutable context passed to both callbacks; may be `NULL`. */
    const void* context;
    /**
     * Decodes a raw value into a C representation; `NULL` if unsupported.
     *
     * `capacity` is the size of `value` in bytes.
     */
    tlv_codec_result_t (*decode)(const void* context, const uint8_t* data, size_t size, void* value,
                                 size_t capacity);
    /**
     * Encodes a C representation into raw value bytes; `NULL` if unsupported.
     *
     * `size` is the size of `value` in bytes. `capacity` is the size of `data`.
     */
    tlv_codec_result_t (*encode)(const void* context, const void* value, size_t size, uint8_t* data,
                                 size_t capacity, size_t* written);
} tlv_codec_t;

/**
 * @brief Decodes a raw value with a codec.
 *
 * `value` is required even for empty representations. The decoded
 * representation may borrow `data`, in which case `data` must outlive it.
 *
 * @param[in]  codec    Codec descriptor.
 * @param[in]  data     Raw value bytes. May be `NULL` only when `size` is zero.
 * @param[in]  size     Raw value size in bytes.
 * @param[out] value    Destination object, correctly typed and aligned.
 * @param[in]  capacity Size of `value` in bytes.
 *
 * @return #TLV_CODEC_OK on success.
 * @return #TLV_CODEC_ERR_NULL_ARG for missing required pointers.
 * @return #TLV_CODEC_ERR_UNSUPPORTED if the codec has no decoder.
 * @return #TLV_CODEC_ERR_BUFFER_TOO_SHORT or #TLV_CODEC_ERR_INVALID_VALUE as
 *         reported by the codec.
 *
 * @warning On error the contents of `value` are unspecified.
 */
TLV_API tlv_codec_result_t tlv_codec_decode(const tlv_codec_t* codec, const uint8_t* data,
                                            size_t size, void* value, size_t capacity);

/**
 * @brief Encodes a C representation into raw value bytes with a codec.
 *
 * With `data == NULL` and `capacity == 0` the value is validated and the
 * exact encoded size is reported in `*written` without writing.
 *
 * @param[in]  codec    Codec descriptor.
 * @param[in]  value    Object to encode, correctly typed and aligned.
 * @param[in]  size     Size of `value` in bytes.
 * @param[out] data     Destination bytes. May be `NULL` only for a size query.
 * @param[in]  capacity Destination capacity in bytes.
 * @param[out] written  Receives the bytes written, or the required size for a
 *                      query. Required; must not alias input or destination.
 *
 * @return #TLV_CODEC_OK on success.
 * @return #TLV_CODEC_ERR_NULL_ARG for missing required pointers.
 * @return #TLV_CODEC_ERR_UNSUPPORTED if the codec has no encoder.
 * @return #TLV_CODEC_ERR_BUFFER_TOO_SHORT or #TLV_CODEC_ERR_INVALID_VALUE as
 *         reported by the codec.
 *
 * @warning On error the destination contents are unspecified and `*written` is zero.
 */
TLV_API tlv_codec_result_t tlv_codec_encode(const tlv_codec_t* codec, const void* value,
                                            size_t size, uint8_t* data, size_t capacity,
                                            size_t* written);

/**
 * @brief Returns a readable description of a codec result.
 *
 * @param result Codec result to describe.
 *
 * @return A static, NUL-terminated string. The caller must not free or modify it.
 */
TLV_API const char* tlv_codec_strerror(tlv_codec_result_t result);

#ifdef __cplusplus
}
#endif

#endif /* OPENTLV_CODEC_H */
