#ifndef OPENTLV_COPY_H
#define OPENTLV_COPY_H

#include "tlv/view.h"
#include "tlv/formats/format.h"
#include "tlv/export.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file
 * @ingroup copy
 * @brief Explicit copies of TLV values and encoded elements into caller-owned storage.
 *
 * Every function here copies into caller-owned storage; none allocates or
 * transfers ownership. The following rules apply to all of them:
 *
 * - With `data == NULL` and `capacity == 0`, the function reports the required
 *   size in `*written` without copying. Otherwise `*written` receives the
 *   number of bytes written on success.
 * - `written` is required and must not alias source or destination storage.
 *   Source descriptors must not overlap destination storage.
 * - On failure `*written` is unchanged. Insufficient capacity returns
 *   #TLV_ERR_BUFFER_TOO_SHORT without modifying `data`.
 * - `NULL` `data` with nonzero capacity, or `NULL` source bytes with nonzero
 *   length, returns #TLV_ERR_NULL_ARG. Empty byte ranges may have `NULL`
 *   source bytes.
 * - A view whose `value.length` does not fit the current build's `size_t`
 *   returns #TLV_ERR_INVALID_LENGTH before any copying.
 */

/** @addtogroup copy
 * @{
 */

/**
 * @brief Copies only a view's value, without interpreting or validating the tag.
 *
 * Overlapping source and destination byte ranges are supported.
 *
 * @param[in]  view     View whose value is copied.
 * @param[out] data     Destination buffer. `NULL` with zero `capacity` queries
 *                      the required size.
 * @param[in]  capacity Destination capacity in bytes.
 * @param[out] written  Receives the value size (the required size for a query).
 *
 * @return #TLV_OK on success.
 * @return #TLV_ERR_NULL_ARG for missing required pointers.
 * @return #TLV_ERR_INVALID_LENGTH if the value length exceeds the native size range.
 * @return #TLV_ERR_BUFFER_TOO_SHORT if `capacity` is insufficient.
 *
 * @see tlv_copy_encoded
 */
TLV_API tlv_result_t tlv_copy_value(const tlv_view_t* view, uint8_t* data, size_t capacity,
                                    size_t* written);

/**
 * @brief Copies an exact encoded byte range, preserving the original wire bytes.
 *
 * The caller identifies the range (for example `input + offset` and
 * `consumed` from tlv_read() or tlv_scan()) as a native pointer/length pair.
 * No framing validation is performed. Overlap is supported.
 *
 * @param[in]  encoded_data   Encoded bytes to copy. May be `NULL` only when
 *                            `encoded_length` is zero.
 * @param[in]  encoded_length Number of bytes to copy.
 * @param[out] data           Destination buffer. `NULL` with zero `capacity`
 *                            queries the required size.
 * @param[in]  capacity       Destination capacity in bytes.
 * @param[out] written        Receives `encoded_length` (the required size for
 *                            a query).
 *
 * @return #TLV_OK on success.
 * @return #TLV_ERR_NULL_ARG for missing required pointers.
 * @return #TLV_ERR_BUFFER_TOO_SHORT if `capacity` is insufficient.
 */
TLV_API tlv_result_t tlv_copy_encoded(const uint8_t* encoded_data, size_t encoded_length,
                                      uint8_t* data, size_t capacity, size_t* written);

/**
 * @brief Serializes a view's tag, length and value using a writer format.
 *
 * Encodes as tlv_write() does. A view does not retain the original header,
 * so the result may differ from the bytes the view was read from; use
 * tlv_copy_encoded() to preserve them exactly.
 *
 * Requires the format's `write_tag`, `write_length` and `length_size`
 * callbacks. The view's value bytes must not overlap the destination element.
 *
 * @param[in]  view     View to serialize.
 * @param[in]  format   Writer format used to encode the element.
 * @param[out] data     Destination buffer. `NULL` with zero `capacity` queries
 *                      the required size.
 * @param[in]  capacity Destination capacity in bytes.
 * @param[out] written  Receives the encoded size.
 *
 * @return #TLV_OK on success.
 * @return #TLV_ERR_NULL_ARG for missing required pointers or callbacks.
 * @return #TLV_ERR_BUFFER_TOO_SHORT if `capacity` is insufficient.
 * @return Any callback error, propagated unchanged.
 *
 * @warning Callback errors may leave `data` modified. Size queries never
 *          write `data`.
 * @see tlv_write, tlv_copy_encoded
 */
TLV_API tlv_result_t tlv_copy_view(const tlv_view_t* view, const tlv_writer_format_t* format,
                                   uint8_t* data, size_t capacity, size_t* written);

#ifdef __cplusplus
}
#endif

/** @} */

#endif /* OPENTLV_COPY_H */
