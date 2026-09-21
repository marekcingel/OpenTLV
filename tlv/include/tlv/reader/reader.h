#ifndef OPENTLV_READER_H
#define OPENTLV_READER_H

#include "tlv/error.h"
#include "tlv/formats/format.h"
#include "tlv/export.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file
 * @ingroup reader
 * @brief Zero-copy parsing of TLV elements from a caller-owned buffer.
 */

/** @addtogroup reader
 * @{
 */

/**
 * @brief Parses one element from the beginning of a buffer.
 *
 * Trailing bytes after the element are ignored. On success `out_entry`
 * borrows the input value (zero-copy) and `consumed` receives the complete
 * encoded size (tag + length + value + optional trailer). The value excludes
 * enclosing framing such as BER EOC. No allocation, value copying, or schema
 * validation occurs.
 *
 * @param[in]  data      Encoded input. May be `NULL` only when `size` is zero,
 *                       which returns #TLV_ERR_END_OF_BUFFER.
 * @param[in]  size      Input size in bytes.
 * @param[in]  format    Reader format; its `read_tag` and `read_length`
 *                       callbacks are required.
 * @param[out] out_entry Receives the parsed element. Required.
 * @param[out] consumed  Receives the encoded size of the element. Required.
 *
 * @return #TLV_OK on success.
 * @return #TLV_ERR_NULL_ARG for missing required pointers or callbacks.
 * @return #TLV_ERR_END_OF_BUFFER for empty input.
 * @return #TLV_ERR_INVALID_TAG if the tag is truncated.
 * @return #TLV_ERR_INVALID_TAG_SIZE for an empty tag or an unsupported tag size.
 * @return #TLV_ERR_INVALID_LENGTH if the length field is truncated.
 * @return #TLV_ERR_BUFFER_TOO_SHORT if the value or trailer is truncated.
 * @return Any callback error, propagated unchanged.
 *
 * @note On failure both outputs remain unchanged.
 * @warning The caller must keep `data` alive while `out_entry->value` is used.
 */
TLV_API tlv_result_t tlv_read(const uint8_t* data, size_t size, const tlv_reader_format_t* format,
                              tlv_view_t* out_entry, size_t* consumed);

/**
 * @brief Sequential reader over a caller-owned buffer.
 *
 * Initialize with tlv_reader_init(). The reader borrows its buffer and
 * format; neither is copied, and both must outlive the reader.
 */
typedef struct tlv_reader {
    /** Borrowed reader format. */
    const tlv_reader_format_t* format;
    /** Borrowed input buffer. */
    const uint8_t* data;
    /** Input size in bytes. */
    size_t size;
    /** Offset of the next element to read. */
    size_t pos;
} tlv_reader_t;

/**
 * @brief Initializes a sequential reader.
 *
 * The reader borrows `data` and `format`; neither is copied.
 *
 * @param[out] reader Reader to initialize.
 * @param[in]  data   Input buffer. May be `NULL` only when `size` is zero.
 * @param[in]  size   Input size in bytes.
 * @param[in]  format Caller-provided reader format.
 *
 * @return #TLV_OK on success.
 * @return #TLV_ERR_NULL_ARG if an argument is `NULL`, or the format lacks a
 *         required callback.
 *
 * @warning The caller must keep `data` and `format` alive for the lifetime
 *          of the reader.
 */
TLV_API tlv_result_t tlv_reader_init(tlv_reader_t* reader, const uint8_t* data, size_t size,
                                     const tlv_reader_format_t* format);

/**
 * @brief Reports whether the reader has consumed all input.
 *
 * @param[in] reader Reader to query.
 *
 * @return 1 if there are no further TLV items, otherwise 0.
 */
TLV_API int tlv_reader_at_end(const tlv_reader_t* reader);

/**
 * @brief Reads the next TLV element and advances the reader.
 *
 * On success `*out_entry` is set and the position advances. The tag is copied
 * into the view; the value points directly into the original buffer
 * (zero-copy).
 *
 * @param[in,out] reader    Reader to advance.
 * @param[out]    out_entry Receives the next element.
 *
 * @return #TLV_OK on success.
 * @return Any error of tlv_read() otherwise.
 *
 * @note On error both the reader position and `*out_entry` remain unchanged.
 * @warning The caller must keep the original buffer alive while the returned
 *          view is used.
 */
TLV_API tlv_result_t tlv_reader_next(tlv_reader_t* reader, tlv_view_t* out_entry);

#ifdef __cplusplus
}
#endif

/** @} */

#endif /* OPENTLV_READER_H */
