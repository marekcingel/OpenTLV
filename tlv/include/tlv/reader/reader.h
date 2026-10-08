// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#ifndef OPENTLV_READER_H
#define OPENTLV_READER_H

#include "tlv/error.h"
#include "tlv/reader/diagnostic.h"
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
 * Trailing bytes after the element are ignored. On success `out_element`
 * borrows the input value and either input or immutable format-supplied identifier
 * storage (see #tlv_tag_binding_t). `consumed` receives the
 * complete encoded size (tag + length + value + optional trailer). The value excludes enclosing
 * framing such as BER EOC. No allocation, value copying, or schema validation occurs.
 *
 * @param[in]  data      Encoded input. May be `NULL` only when `size` is zero,
 *                       which returns #TLV_ERR_END_OF_BUFFER.
 * @param[in]  size      Input size in bytes.
 * @param[in]  format    Readable canonical format descriptor.
 * @param[out] out_element Receives the parsed element. Required.
 * @param[out] consumed  Receives the encoded size of the element. Required.
 *
 * @return #TLV_OK on success.
 * @return #TLV_ERR_NULL_ARG for missing required pointers or callbacks.
 * @return #TLV_ERR_END_OF_BUFFER for empty input.
 * @return #TLV_ERR_INVALID_TAG if the tag is malformed.
 * @return #TLV_ERR_INVALID_TAG_SIZE for an empty tag or an unsupported tag size.
 * @return #TLV_ERR_INVALID_LENGTH if the length field is malformed.
 * @return #TLV_ERR_BUFFER_TOO_SHORT if the header, value or trailer is incomplete.
 * @return A permitted decoder error, propagated unchanged. Invalid control statuses,
 * unknown callback results and invalid successful outputs become #TLV_ERR_CALLBACK;
 * see #tlv_decode_fn.
 *
 * @note On failure both outputs remain unchanged.
 * @warning The caller must keep `data` alive and unchanged while any part of `out_element` is used.
 *          Format-supplied identifier storage must likewise outlive every retained Tag.
 */
TLV_API tlv_result_t tlv_read(const uint8_t* data, size_t size, const tlv_format_t* format,
                              tlv_element_t* out_element, size_t* consumed);

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
 * @param[in]  format         Readable canonical format descriptor.
 * @param[out] out_element      Receives the parsed element. Required.
 * @param[out] consumed       Receives the encoded size of the element. Required.
 * @param[out] out_diagnostic Receives detail on failure; may be `NULL`.
 *
 * @return Same as tlv_read().
 *
 * @note On failure both `out_element` and `consumed` remain unchanged.
 * @note On success `*out_diagnostic` is left unchanged.
 * @warning The caller must keep `data` alive while `out_element->value` or
 *          `out_diagnostic->tag` is used.
 */
TLV_API tlv_result_t tlv_read_diag(const uint8_t* data, size_t size, const tlv_format_t* format,
                                   tlv_element_t* out_element, size_t* consumed,
                                   tlv_reader_diagnostic_t* out_diagnostic);

/**
 * @brief Canonical pull-based cursor over a caller-owned input buffer.
 *
 * Initialize with tlv_reader_init() or tlv_reader_init_incremental(). The
 * reader borrows its current input and Format without copying. Format and its
 * context must outlive the reader. Input must remain valid until replaced and
 * while any borrowed result referring to it is used.
 * The caller requests each element with tlv_reader_next(); no I/O, buffering,
 * allocation, schema validation, semantic decoding or recovery occurs. Format
 * alone interprets the wire representation. Higher-level traversal composes
 * this cursor rather than implementing another sequential parser.
 *
 * Only a successful read advances `pos`, by the complete encoded extent,
 * including any trailer. End, incomplete input and errors preserve the cursor
 * and success outputs. Repeating a call with unchanged input/state returns the
 * same outcome. tlv_reader_init_incremental() starts non-final input;
 * tlv_reader_set_input() supplies a replacement contiguous window without
 * copying, retaining partial fields, or performing I/O. Incomplete elements
 * are retried from their start through Format when more bytes are supplied.
 * The caller must retain the complete unconsumed prefix, not the entire stream.
 *
 * Returned elements and sources do not borrow the cursor itself. Advancing or
 * reinitializing it does not invalidate them; their input and format-supplied
 * identifier storage must remain alive and unchanged while results are used.
 * @see @docs{guides/memory,format context ownership and lifetime}
 */
typedef struct tlv_reader {
    /** Borrowed reader format. */
    const tlv_format_t* format;
    /** Borrowed input buffer. */
    const uint8_t* data;
    /** Input size in bytes. */
    size_t size;
    /** Offset of the next element in data, in bytes; must not exceed size. */
    size_t pos;
    /** Absolute logical byte offset of data[0]; offsets are bounded by SIZE_MAX. */
    size_t base_offset;
    /** Nonzero when no bytes may be appended; set through initialization or set_input. */
    int final_input;
} tlv_reader_t;

/**
 * @brief Initializes a sequential reader over a complete, final input buffer.
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
 * @note On failure the reader remains unchanged. On success position is zero,
 *       including when reinitializing a previously used reader.
 *
 * @warning Format and its context must outlive the reader. Input must remain
 *          valid until replaced and while any retained borrowed result uses it.
 */
TLV_API tlv_result_t tlv_reader_init(tlv_reader_t* reader, const uint8_t* data, size_t size,
                                     const tlv_format_t* format);

/**
 * @brief Initializes a non-final, incremental Reader at absolute offset zero.
 *
 * @param[out] reader Required cursor; unchanged on failure.
 * @param[in] data Borrowed contiguous input, NULL only when size is zero.
 * @param[in] size Available bytes, including any incomplete element prefix.
 * @param[in] format Required readable Format; borrowed with its context.
 * @return #TLV_OK on success.
 * @return #TLV_ERR_NULL_ARG for missing required pointers or decode callback.
 * @note No allocation or copying occurs. Empty input yields #TLV_NEED_MORE_DATA.
 * @warning Input and Format storage must obey the lifetime contract of #tlv_reader_t.
 */
TLV_API tlv_result_t tlv_reader_init_incremental(tlv_reader_t* reader, const uint8_t* data,
                                                 size_t size, const tlv_format_t* format);

/**
 * @brief Extends or replaces the caller-owned contiguous input window.
 *
 * Discard only an already consumed prefix: `discard <= reader->pos`.
 * The new window must begin with exactly the old bytes from `discard` through
 * the old window end, followed by optional additional bytes. Thus its size
 * must be at least `reader->size - discard`. Prefix identity is a caller
 * precondition; Reader does not compare or dereference the old window, which
 * may already have been relocated. No bytes are copied or retained internally.
 * On success base_offset increases by discard, pos decreases by discard,
 * and the absolute cursor position is unchanged.
 *
 * @param[in,out] reader Initialized cursor; required.
 * @param[in] data New contiguous window, NULL only when size is zero.
 * @param[in] size New available byte count.
 * @param[in] discard Number of bytes removed from the old window's beginning.
 * @param[in] final_input Exactly 0 or 1; 1 declares EOF at the new window end.
 * @return #TLV_OK on success.
 * @return #TLV_ERR_NULL_ARG for missing required pointers or Format callback.
 * @return #TLV_ERR_INVALID_ARG for corrupt cursor fields, discard, size or final flag;
 * #TLV_ERR_INVALID_STATE for reopening or extending finalized input;
 *         final input cannot be reopened or extended without reinitialization.
 * @return #TLV_ERR_OVERFLOW if the new absolute window end exceeds SIZE_MAX.
 * @note On failure the cursor is unchanged. After EOF, rebinding and discarding
 *       consumed bytes remain allowed if the absolute end is unchanged.
 * @warning All retained elements, sources and diagnostics still borrow their
 *          original storage. Relocating or overwriting it invalidates them;
 *          this operation cannot transfer existing views to the new buffer.
 */
TLV_API tlv_result_t tlv_reader_set_input(tlv_reader_t* reader, const uint8_t* data, size_t size,
                                          size_t discard, int final_input);

/**
 * @brief Returns the consumed prefix size in the current window.
 * @param[in] reader Initialized cursor, or NULL.
 * @return reader->pos in bytes, or zero for NULL.
 * @note These bytes may be discarded only after borrowed views into them are released.
 */
TLV_API size_t tlv_reader_consumed(const tlv_reader_t* reader);

/**
 * @brief Returns the absolute logical offset of the next element.
 * @param[in] reader Initialized cursor with unmodified valid state, or NULL.
 * @return base_offset + pos in bytes, or zero for NULL. Bounded by SIZE_MAX.
 */
TLV_API size_t tlv_reader_offset(const tlv_reader_t* reader);

/**
 * @brief Reports whether the reader has consumed all input.
 *
 * @param[in] reader Reader to query.
 *
 * @return 1 if input is final and position equals input size, otherwise 0 (also for `NULL`).
 * @note This checks exhaustion only; it does not parse or validate remaining bytes.
 */
TLV_API int tlv_reader_at_end(const tlv_reader_t* reader);

/**
 * @brief Reads the next TLV element and advances the reader.
 *
 * On success `*out_element` is set and the position advances. Value borrows the
 * input; Tag borrows input or immutable format storage as in tlv_read().
 * No bytes are copied.
 *
 * @param[in,out] reader    Reader to advance.
 * @param[out]    out_element Receives the next element.
 *
 * @return #TLV_OK when an element is available.
 * @return #TLV_ERR_END_OF_BUFFER when final input has been fully consumed.
 * @return #TLV_NEED_MORE_DATA when non-final input is exhausted or Format
 *         reports incomplete input. No partial element is published or consumed.
 * @return #TLV_ERR_BUFFER_TOO_SHORT when final input contains an incomplete element.
 * @return Any other tlv_read() error for invalid input or arguments.
 * @return #TLV_ERR_INVALID_ARG if position exceeds input size.
 * @return #TLV_ERR_OVERFLOW if the absolute input extent exceeds SIZE_MAX.
 *
 * @note On error both the reader position and `*out_element` remain unchanged.
 * @warning The caller must keep the original buffer alive while the returned
 *          element is used.
 */
TLV_API tlv_result_t tlv_reader_next(tlv_reader_t* reader, tlv_element_t* out_element);

/**
 * @brief Reads the next TLV element and advances the reader, with diagnostic detail on failure.
 *
 * Behaves exactly like tlv_reader_next(); additionally, when `out_diagnostic`
 * is not `NULL` and the read fails, it is filled with detail about the
 * failure or #TLV_NEED_MORE_DATA. Diagnostic offsets are absolute across input
 * windows (base_offset plus the local offset). Required region extent is
 * exposed when known; need-more-data diagnostics have informational severity.
 *
 * @param[in,out] reader         Reader to advance.
 * @param[out]    out_element      Receives the next element.
 * @param[out]    out_diagnostic Receives detail on failure; may be `NULL`.
 *
 * @return Same as tlv_reader_next().
 *
 * @note On error the reader position and `*out_element` remain unchanged.
 * @note On success `*out_diagnostic` is left unchanged.
 */
TLV_API tlv_result_t tlv_reader_next_diag(tlv_reader_t* reader, tlv_element_t* out_element,
                                          tlv_reader_diagnostic_t* out_diagnostic);

/**
 * @brief Pulls one element and its borrowed source metadata in one decode.
 *
 * Behaves like tlv_reader_next_diag(), also publishing the source on success.
 * Source ranges remain relative to `source->data`, the element's start; its
 * absolute logical offset is tlv_reader_offset() before the call.
 * Diagnostic offsets are absolute across input windows.
 *
 * @param[in,out] reader Cursor initialized by tlv_reader_init(); required.
 * @param[out] out_element Receives the semantic element; required.
 * @param[out] source Receives the source and framing ranges; required.
 * @param[out] out_diagnostic Optional structured failure detail; may be `NULL`.
 * @return Same outcomes as tlv_reader_next().
 * @note On non-success the cursor, element and source remain unchanged.
 *       On success the diagnostic remains unchanged. No allocation occurs.
 * @warning Input bytes, Format and context must outlive retained sources and
 *          remain unchanged; format-supplied identifier storage must outlive Tags.
 */
TLV_API tlv_result_t tlv_reader_next_source_diag(tlv_reader_t* reader, tlv_element_t* out_element,
                                                 tlv_source_t* source,
                                                 tlv_reader_diagnostic_t* out_diagnostic);

/**
 * @brief Decode once, returning semantic content, source information and failure detail.
 *
 * @param[in]  data       Input, NULL only when size is zero.
 * @param[in]  size       Available native bytes.
 * @param[in]  format     Readable descriptor.
 * @param[out] element    Semantic result.
 * @param[out] consumed   Complete encoded size.
 * @param[out] source     Borrowed immutable source; required.
 * @param[out] diagnostic Optional failure detail.
 *
 * @return Same results as tlv_read_diag(). All success outputs remain unchanged on failure.
 *
 * @warning Source bytes and format/context must outlive source and remain unchanged.
 */
TLV_API tlv_result_t tlv_read_source_diag(const uint8_t* data, size_t size,
                                          const tlv_format_t* format, tlv_element_t* element,
                                          size_t* consumed, tlv_source_t* source,
                                          tlv_reader_diagnostic_t* diagnostic);

#ifdef __cplusplus
}
#endif

/** @} */

#endif /* OPENTLV_READER_H */
