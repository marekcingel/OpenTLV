#ifndef OPENTLV_WRITER_H
#define OPENTLV_WRITER_H

#include "tlv/formats/format.h"
#include "tlv/export.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file
 * @ingroup writer
 * @brief Allocation-free encoding of TLV elements into caller-owned buffers.
 */

/** @addtogroup writer
 * @{
 */

/**
 * @brief Computes the encoded size of an element without accessing value bytes.
 *
 * Requires the format's `write_tag`, `write_length` and `length_size`
 * callbacks.
 *
 * @param[in]  tag    Element tag.
 * @param[in]  length Value length in bytes.
 * @param[in]  format Writer format.
 * @param[out] size   Receives the size of tag + length + value. Required.
 *
 * @return #TLV_OK on success.
 * @return #TLV_ERR_NULL_ARG for a missing output or callback.
 * @return #TLV_ERR_INVALID_TAG_SIZE for an empty tag or an unsupported tag size.
 * @return #TLV_ERR_INVALID_LENGTH if the total overflows `size_t`.
 * @return Any callback error, propagated unchanged.
 *
 * @note On failure `*size` is unchanged.
 */
TLV_API tlv_result_t tlv_encoded_size(tlv_tag_t tag, size_t length,
                                      const tlv_writer_format_t* format, size_t* size);

/**
 * @brief Encodes one element directly into caller-owned memory.
 *
 * Neither allocates nor interprets the value. Capacity is checked before
 * writing, against the complete required size (tag + length + value),
 * computed the same way as tlv_encoded_size() for the same tag, length and
 * format. Requires the same callbacks as sizing.
 *
 * On success `*written` receives that size and `data` holds the encoded
 * element. On insufficient capacity `*written` also receives the required
 * size (matching tlv_encoded_size()), `data` is left unchanged, and the
 * result is #TLV_ERR_BUFFER_TOO_SHORT.
 *
 * @param[out] data     Destination buffer. May be `NULL` only if `capacity` is zero.
 * @param[in]  capacity Destination capacity in bytes.
 * @param[in]  format   Writer format.
 * @param[in]  tag      Element tag.
 * @param[in]  value    Value bytes. May be `NULL` only for an empty value.
 *                      Must not overlap the destination element.
 * @param[in]  length   Value length in bytes.
 * @param[out] written  Receives the encoded size. Required.
 *
 * @return #TLV_OK on success.
 * @return #TLV_ERR_NULL_ARG for invalid arguments.
 * @return #TLV_ERR_BUFFER_TOO_SHORT if `capacity` is insufficient.
 * @return Any callback error, propagated unchanged.
 *
 * @warning Every failure other than the capacity check leaves `*written`
 *          unchanged (including a callback returning
 *          #TLV_ERR_BUFFER_TOO_SHORT), and such callback errors may still
 *          have modified `data`.
 * @see tlv_encoded_size
 */
TLV_API tlv_result_t tlv_write(uint8_t* data, size_t capacity, const tlv_writer_format_t* format,
                               tlv_tag_t tag, const uint8_t* value, size_t length, size_t* written);

/**
 * @brief Sequential writer over a caller-owned buffer.
 *
 * Initialize with tlv_writer_init(). The writer never allocates; it borrows
 * its format and buffer, which must outlive it.
 */
typedef struct tlv_writer {
    /** Borrowed writer format. */
    const tlv_writer_format_t* format;
    /** Buffer provided by the caller; the core never allocates. */
    uint8_t* buf;
    /** Capacity of `buf` in bytes. */
    size_t capacity;
    /** Number of bytes currently written. */
    size_t pos;
} tlv_writer_t;

/**
 * @brief Initializes a sequential writer.
 *
 * @param[out] writer   Writer to initialize.
 * @param[in]  buf      Caller-provided output buffer.
 * @param[in]  capacity Buffer capacity in bytes.
 * @param[in]  format   Caller-provided writer format.
 *
 * @return #TLV_OK on success.
 * @return #TLV_ERR_NULL_ARG if `writer` or `format` is `NULL`, `buf` is `NULL`
 *         with a nonzero `capacity`, or the format lacks a required callback.
 *         A `NULL` `buf` with zero `capacity` is accepted.
 *
 * @warning The caller must keep `buf` and `format` alive for the lifetime
 *          of the writer.
 */
TLV_API tlv_result_t tlv_writer_init(tlv_writer_t* writer, uint8_t* buf, size_t capacity,
                                     const tlv_writer_format_t* format);

/**
 * @brief Writes one TLV element at the writer's current position.
 *
 * Does not expose the required size on insufficient capacity; use tlv_write()
 * or tlv_encoded_size() directly for that feedback.
 *
 * @param[in,out] writer Writer to append to.
 * @param[in]     tag    Element tag.
 * @param[in]     value  Value bytes; may be `NULL` only for an empty value.
 * @param[in]     length Value length in bytes.
 *
 * @return #TLV_OK on success; the position advances by the encoded size.
 * @return Any error of tlv_write() otherwise.
 *
 * @note On error the position is unchanged.
 * @warning Callbacks may have modified buffer bytes on error.
 */
TLV_API tlv_result_t tlv_writer_write(tlv_writer_t* writer, tlv_tag_t tag, const uint8_t* value,
                                      size_t length);

/**
 * @brief Appends a view at the writer's current position.
 *
 * Serializes with `writer->format`, following the same argument, overlap and
 * callback-error contracts as tlv_copy_view().
 *
 * Unlike tlv_copy_view(), a `NULL` writer buffer with zero remaining capacity
 * is treated as a real destination rather than a size query. Every element
 * has a nonzero encoded size (tag and length), even with an empty value, so
 * the call then returns #TLV_ERR_BUFFER_TOO_SHORT.
 *
 * @param[in,out] writer Writer to append to.
 * @param[in]     view   View to serialize.
 *
 * @return #TLV_OK on success; the position advances by the encoded size.
 * @return #TLV_ERR_NULL_ARG if `writer` is `NULL`.
 * @return #TLV_ERR_BUFFER_TOO_SHORT if `pos > capacity` or capacity is insufficient.
 * @return Any error of tlv_copy_view(), propagated unchanged.
 *
 * @note On any failure, including insufficient capacity, the position is
 *       unchanged and the required size is not exposed; use
 *       tlv_encoded_size() for that.
 * @see tlv_copy_view
 */
TLV_API tlv_result_t tlv_writer_copy_view(tlv_writer_t* writer, const tlv_view_t* view);

/**
 * @brief Appends an exact encoded byte range at the writer's current position.
 *
 * Copies without framing validation or format conversion, preserving the
 * original wire bytes as tlv_copy_encoded() does. Overlapping byte ranges are
 * supported.
 *
 * As with tlv_writer_copy_view(), a `NULL` writer buffer with zero remaining
 * capacity is a real destination, not a size query: copying a nonzero-length
 * range returns #TLV_ERR_BUFFER_TOO_SHORT, while copying an empty range may
 * succeed without advancing the position.
 *
 * @param[in,out] writer         Writer to append to.
 * @param[in]     encoded_data   Encoded bytes to copy; may be `NULL` only
 *                               when `encoded_length` is zero.
 * @param[in]     encoded_length Number of bytes to copy.
 *
 * @return #TLV_OK on success; the position advances by `encoded_length`.
 * @return #TLV_ERR_NULL_ARG if `writer` is `NULL`.
 * @return #TLV_ERR_BUFFER_TOO_SHORT if `pos > capacity` or capacity is insufficient.
 *
 * @note On failure the position is unchanged.
 * @see tlv_copy_encoded
 */
TLV_API tlv_result_t tlv_writer_copy_encoded(tlv_writer_t* writer, const uint8_t* encoded_data,
                                             size_t encoded_length);

/**
 * @brief Returns the number of bytes currently written to the buffer.
 *
 * @param[in] writer Writer to query.
 *
 * @return The current write position in bytes, or 0 if `writer` is `NULL`.
 */
TLV_API size_t tlv_writer_size(const tlv_writer_t* writer);

#ifdef __cplusplus
}
#endif

/** @} */

#endif /* OPENTLV_WRITER_H */
