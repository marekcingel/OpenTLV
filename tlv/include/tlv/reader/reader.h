#ifndef OPENTLV_READER_H
#define OPENTLV_READER_H

#include "tlv/error.h"
#include "tlv/diagnostic.h"
#include "tlv/format.h"
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

/** @brief Which parsing step a #tlv_reader_diagnostic_t reports on. */
typedef enum tlv_reader_operation {
    /** Decoding the tag. */
    TLV_READER_OP_TAG = 0,
    /** Decoding the length field, or the header for a whole-element format. */
    TLV_READER_OP_LENGTH,
    /** Checking the value against the bytes available or an enclosing boundary. */
    TLV_READER_OP_VALUE,
    /** Checking trailing framing, such as a BER end-of-contents marker. */
    TLV_READER_OP_TRAILER
} tlv_reader_operation_t;

/**
 * @brief Structured detail for a failed tlv_read() or tlv_reader_next() call.
 *
 * Pairs a #tlv_diagnostic_t with the reader-specific state needed to locate a
 * parsing failure precisely: which step failed, the tag being processed if
 * one was already decoded, the offsets of the fields involved, and the sizes
 * that made the operation fail. Every field is a fixed-size value or a
 * borrowed pointer, so filling one never allocates; `tag`, like any
 * #tlv_tag_t a reader produces, borrows the input buffer that was parsed.
 *
 * A field not applicable to the failure that produced the diagnostic is left
 * unset, indicated by its paired `has_*` flag being zero.
 *
 * @see tlv_reader_diagnostic_init
 */
typedef struct tlv_reader_diagnostic {
    /** Code, severity, the offset of the failing field, and any expected/actual text. */
    tlv_diagnostic_t diagnostic;
    /** Parsing step that failed. */
    tlv_reader_operation_t operation;
    /** Nonzero if `tag` was decoded before the failure. */
    int has_tag;
    /** Tag being processed; valid only if `has_tag` is nonzero. */
    tlv_tag_t tag;
    /** Nonzero if `tag_offset` is set. */
    int has_tag_offset;
    /** Offset of the tag field; valid only if `has_tag_offset` is nonzero. */
    size_t tag_offset;
    /** Nonzero if `length_offset` is set. */
    int has_length_offset;
    /** Offset of the length field; valid only if `has_length_offset` is nonzero. */
    size_t length_offset;
    /** Nonzero if `value_offset` is set. */
    int has_value_offset;
    /** Offset of the value; valid only if `has_value_offset` is nonzero. */
    size_t value_offset;
    /** Nonzero if `declared_length` is set. */
    int has_declared_length;
    /**
     * Length declared for the field named by `operation` (the value, or the
     * missing trailer); valid only if `has_declared_length` is nonzero.
     */
    size_t declared_length;
    /** Nonzero if `available` is set. */
    int has_available;
    /** Bytes actually available at the failing offset; valid only if `has_available` is nonzero. */
    size_t available;
    /** Nonzero if `enclosing_end` is set. */
    int has_enclosing_end;
    /**
     * Offset one past the last byte the element may use: the end of the
     * input, or, for a nested read bounded to a parent's value, the end of
     * that enclosing value. Valid only if `has_enclosing_end` is nonzero.
     */
    size_t enclosing_end;
} tlv_reader_diagnostic_t;

/**
 * @brief Resets a reader diagnostic to all-unset.
 *
 * @param[out] diagnostic Diagnostic to initialize; must not be `NULL`.
 */
TLV_API void tlv_reader_diagnostic_init(tlv_reader_diagnostic_t* diagnostic);

/**
 * @brief Parses one element from the beginning of a buffer, with diagnostic detail on failure.
 *
 * Behaves exactly like tlv_read(); additionally, when `out_diagnostic` is not
 * `NULL` and parsing fails, it is filled with detail about the failure.
 *
 * @param[in]  data           Encoded input. May be `NULL` only when `size` is zero.
 * @param[in]  size           Input size in bytes.
 * @param[in]  format         Reader format; its `read_tag` and `read_length`
 *                            callbacks are required.
 * @param[out] out_entry      Receives the parsed element. Required.
 * @param[out] consumed       Receives the encoded size of the element. Required.
 * @param[out] out_diagnostic Receives detail on failure; may be `NULL`.
 *
 * @return Same as tlv_read().
 *
 * @note On failure both `out_entry` and `consumed` remain unchanged.
 * @note On success `*out_diagnostic` is left unchanged.
 * @warning The caller must keep `data` alive while `out_entry->value` or
 *          `out_diagnostic->tag` is used.
 */
TLV_API tlv_result_t tlv_read_diag(const uint8_t* data, size_t size,
                                   const tlv_reader_format_t* format, tlv_view_t* out_entry,
                                   size_t* consumed, tlv_reader_diagnostic_t* out_diagnostic);

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

/**
 * @brief Reads the next TLV element and advances the reader, with diagnostic detail on failure.
 *
 * Behaves exactly like tlv_reader_next(); additionally, when `out_diagnostic`
 * is not `NULL` and the read fails, it is filled with detail about the
 * failure. Offsets in `*out_diagnostic` are absolute within the reader's
 * buffer, not relative to the element that was being read.
 *
 * @param[in,out] reader         Reader to advance.
 * @param[out]    out_entry      Receives the next element.
 * @param[out]    out_diagnostic Receives detail on failure; may be `NULL`.
 *
 * @return Same as tlv_reader_next().
 *
 * @note On error the reader position and `*out_entry` remain unchanged.
 * @note On success `*out_diagnostic` is left unchanged.
 */
TLV_API tlv_result_t tlv_reader_next_diag(tlv_reader_t* reader, tlv_view_t* out_entry,
                                          tlv_reader_diagnostic_t* out_diagnostic);

#ifdef __cplusplus
}
#endif

/** @} */

#endif /* OPENTLV_READER_H */
