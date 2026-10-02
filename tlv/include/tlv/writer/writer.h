// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#ifndef OPENTLV_WRITER_H
#define OPENTLV_WRITER_H

#include "tlv/error.h"
#include "tlv/diagnostic.h"
#include "tlv/format.h"
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
 * Requires the format's `measure` and `encode` callbacks. Only suitable for
 * formats that can measure without reading Value; otherwise use
 * tlv_element_encoded_size() with readable content. Never allocates.
 *
 * @param[in]  tag    Element tag.
 * @param[in]  length Value length in bytes.
 * @param[in]  format Writer format.
 * @param[out] size   Receives Header + Value + Trailer size. Required.
 *
 * @return #TLV_OK on success.
 * @return #TLV_ERR_NULL_ARG for a missing output or callback.
 * @return #TLV_ERR_NATIVE_SIZE if the total cannot fit in `size_t`.
 * @return #TLV_ERR_OVERFLOW if logical size arithmetic overflows.
 * @return Any callback error, propagated unchanged.
 *
 * @note On failure `*size` is unchanged.
 */
TLV_API tlv_result_t tlv_encoded_size(tlv_tag_t tag, size_t length, const tlv_format_t* format,
                                      size_t* size);

/**
 * @brief Encodes one element directly into caller-owned memory.
 *
 * Neither allocates nor interprets the value. Capacity is checked before
 * writing, against the complete required size (Header + Value + Trailer),
 * computed by measuring the semantic Element. Requires the same callbacks
 * as sizing. Content-independent formats also support tlv_encoded_size().
 *
 * On success `*written` receives that size and `data` holds the encoded
 * element. On insufficient capacity `*written` also receives the required
 * size (matching tlv_element_encoded_size()), `data` is left unchanged, and the
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
TLV_API tlv_result_t tlv_write(uint8_t* data, size_t capacity, const tlv_format_t* format,
                               tlv_tag_t tag, const uint8_t* value, size_t length, size_t* written);

/**
 * @brief Which encoding step a #tlv_writer_diagnostic_t reports on.
 */
typedef enum tlv_writer_operation {
    /** Encoding an explicit identifier field. */
    TLV_WRITER_OP_TAG = 0,
    /** Encoding or sizing the length field. */
    TLV_WRITER_OP_LENGTH,
    /** Checking the encoded element against the destination capacity. */
    TLV_WRITER_OP_VALUE,
    /** Entire header or unnamed header field. */
    TLV_WRITER_OP_HEADER,
    /** Trailing framing. */
    TLV_WRITER_OP_TRAILER,
    /** Copying an unvalidated encoded byte range. */
    TLV_WRITER_OP_COPY,
    /** Checking and preserving original source bytes. */
    TLV_WRITER_OP_PRESERVE,
    /** Opening a constructed element or checking tree resource limits. */
    TLV_WRITER_OP_BEGIN,
    /** Closing a constructed element or checking its workspace capacity. */
    TLV_WRITER_OP_END
} tlv_writer_operation_t;

/**
 * @brief Structured detail for a failed tlv_write() or tlv_writer_write() call.
 *
 * Pairs a #tlv_diagnostic_t with the writer-specific state needed to explain
 * an encoding failure: which step failed, the tag supplied by the caller,
 * the value length that was requested, the total encoded
 * size that was required, and the destination capacity that was available.
 * Every field is a fixed-size value or a borrowed pointer, so filling one
 * never allocates; `tag` borrows the tag passed to the failing call.
 *
 * A field not applicable to the failure that produced the diagnostic is left
 * unset, indicated by its paired `has_*` flag being zero.
 *
 * @see tlv_writer_diagnostic_init
 */
typedef struct tlv_writer_diagnostic {
    /** Code, severity and failing field offset, or element start if no field offset is known.
     * Sequential operations report absolute buffer offsets; sizing uses element-relative offsets.
     * An unrepresentable absolute offset is unset. */
    tlv_diagnostic_t diagnostic;
    /** Encoding step that failed. */
    tlv_writer_operation_t operation;
    /**
     * Nonzero if an Element was supplied, even if its tag is invalid.
     */
    int has_tag;
    /** Tag that was being encoded; valid only if `has_tag` is nonzero, and may itself be the
     * cause of the failure (for example an unsupported size). */
    tlv_tag_t tag;
    /** Nonzero if the supplied logical Value size fits the native `length` field. */
    int has_length;
    /** Value length that was requested; valid only if `has_length` is nonzero. */
    size_t length;
    /** Nonzero if `required` is set. */
    int has_required;
    /**
     * Total encoded size required (Header + Value + Trailer); valid
     * only if `has_required` is nonzero.
     */
    size_t required;
    /** Nonzero if `available` is set. */
    int has_available;
    /** Destination bytes available at the element start; valid only if `has_available`
     * is nonzero. */
    size_t available;
} tlv_writer_diagnostic_t;

/**
 * @brief Resets a writer diagnostic to all-unset.
 *
 * @param[out] diagnostic Diagnostic to initialize; NULL is ignored.
 */
TLV_API void tlv_writer_diagnostic_init(tlv_writer_diagnostic_t* diagnostic);

/**
 * @brief Measures exact native output storage for a semantic Element without allocating.
 *
 * Delegates to Format measure, including content-dependent sizing. No output
 * buffer is needed. Logical sizes are checked before conversion to size_t.
 * @param[in] element Semantic input; required. Value may be NULL for sizing only
 *                    when the format does not inspect its content.
 * @param[in] format Borrowed writable format; required.
 * @param[out] size Required native byte count, including Header and Trailer; required.
 * @return #TLV_OK on success, #TLV_ERR_NULL_ARG for missing arguments,
 *         #TLV_ERR_NATIVE_SIZE for a non-native total, or a Format error.
 * @note On failure *size is unchanged. Input is not retained.
 */
TLV_API tlv_result_t tlv_element_encoded_size(const tlv_element_t* element,
                                              const tlv_format_t* format, size_t* size);

/**
 * @brief Measures an Element with optional structured failure information.
 * @param[in] element Semantic input as for tlv_element_encoded_size().
 * @param[in] format Borrowed writable format.
 * @param[out] size Required native byte count; required, unchanged on failure.
 * @param[out] diagnostic Optional diagnostic, unchanged on success. No capacity is set.
 * @return Same as tlv_element_encoded_size(). Never allocates.
 */
TLV_API tlv_result_t tlv_element_encoded_size_diag(const tlv_element_t* element,
                                                   const tlv_format_t* format, size_t* size,
                                                   tlv_writer_diagnostic_t* diagnostic);

/**
 * @brief Encodes a semantic Element into caller-owned storage without allocating.
 * @param[out] data Destination; NULL only with zero capacity. Must not overlap input.
 * @param[in] capacity Native destination capacity in bytes.
 * @param[in] format Borrowed writable format; required.
 * @param[in] element Semantic input; required, with readable Value for nonzero size.
 * @param[out] written Required output: bytes written, or required size on preflight
 *                     capacity failure; unchanged on other failures.
 * @return #TLV_OK on success, or the error from tlv_format_encode().
 * @note A NULL, zero-capacity destination is a real write, not a sizing query.
 * @warning Encoder callback failures may modify destination bytes. Input is not retained.
 */
TLV_API tlv_result_t tlv_write_element(uint8_t* data, size_t capacity, const tlv_format_t* format,
                                       const tlv_element_t* element, size_t* written);

/**
 * @brief Encodes an Element with optional structured failure information.
 * @param[out] data Caller-owned destination as for tlv_write_element().
 * @param[in] capacity Native destination capacity in bytes.
 * @param[in] format Borrowed writable format.
 * @param[in] element Semantic input; required.
 * @param[out] written Required size output with tlv_write_element() semantics.
 * @param[out] diagnostic Optional diagnostic; unchanged on success.
 * @return Same as tlv_write_element(), including callback-error buffer semantics.
 */
TLV_API tlv_result_t tlv_write_element_diag(uint8_t* data, size_t capacity,
                                            const tlv_format_t* format,
                                            const tlv_element_t* element, size_t* written,
                                            tlv_writer_diagnostic_t* diagnostic);

/**
 * @brief Encodes one element directly into caller-owned memory, with diagnostic detail on failure.
 *
 * Behaves exactly like tlv_write(); additionally, when `out_diagnostic` is not
 * `NULL` and encoding fails, it is filled with detail about the failure.
 *
 * @param[in]  data           Destination buffer. May be `NULL` only if `capacity` is zero.
 * @param[in]  capacity       Destination capacity in bytes.
 * @param[in]  format         Writer format.
 * @param[in]  tag            Element tag.
 * @param[in]  value          Value bytes. May be `NULL` only for an empty value.
 *                            Must not overlap the destination element.
 * @param[in]  length         Value length in bytes.
 * @param[out] written        Receives the encoded size, or the required size on
 *                            insufficient capacity. Required.
 * @param[out] out_diagnostic Receives detail on failure; may be `NULL`.
 *
 * @return Same as tlv_write().
 *
 * @note On success `*out_diagnostic` is left unchanged.
 * @see tlv_write
 */
TLV_API tlv_result_t tlv_write_diag(uint8_t* data, size_t capacity, const tlv_format_t* format,
                                    tlv_tag_t tag, const uint8_t* value, size_t length,
                                    size_t* written, tlv_writer_diagnostic_t* out_diagnostic);

/**
 * @brief Sequential writer over a caller-owned buffer.
 *
 * Initialize with tlv_writer_init(). The writer never allocates; it borrows
 * its format and buffer, which must outlive it, transitively including the
 * format's own context.
 * @see @docs{guides/memory,format context ownership and lifetime}
 */
typedef struct tlv_writer {
    /** Borrowed writer format. */
    const tlv_format_t* format;
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
                                     const tlv_format_t* format);

/**
 * @brief Writes one TLV element at the writer's current position.
 *
 * Does not expose the required size on insufficient capacity; use tlv_write()
 * or tlv_element_encoded_size() directly for that feedback.
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
 * @brief Writes one TLV element at the writer's current position, with diagnostic detail on
 * failure.
 *
 * Behaves exactly like tlv_writer_write(); additionally, when `out_diagnostic`
 * is not `NULL` and the write fails, it is filled with detail about the
 * failure. The diagnostic's offset is absolute within the writer's buffer:
 * the failing field offset, or the element start if no field offset is known.
 *
 * @param[in,out] writer         Writer to append to.
 * @param[in]     tag            Element tag.
 * @param[in]     value          Value bytes; may be `NULL` only for an empty value.
 * @param[in]     length         Value length in bytes.
 * @param[out]    out_diagnostic Receives detail on failure; may be `NULL`.
 *
 * @return Same as tlv_writer_write().
 *
 * @note On error the position is unchanged.
 * @note On success `*out_diagnostic` is left unchanged.
 * @warning Callbacks may have modified buffer bytes on error.
 */
TLV_API tlv_result_t tlv_writer_write_diag(tlv_writer_t* writer, tlv_tag_t tag,
                                           const uint8_t* value, size_t length,
                                           tlv_writer_diagnostic_t* out_diagnostic);

/**
 * @brief Re-encodes an Element at the writer's current position.
 *
 * Serializes with `writer->format`, following the same argument, overlap and
 * callback-error contracts as tlv_copy_element().
 *
 * Unlike tlv_copy_element(), a `NULL` writer buffer with zero remaining capacity
 * is treated as a real destination rather than a size query. Every element
 * has a nonzero encoded size under the Format contract, even with an empty value, so
 * the call then returns #TLV_ERR_BUFFER_TOO_SHORT.
 *
 * @param[in,out] writer Writer to append to.
 * @param[in]     element   Element to serialize.
 *
 * @return #TLV_OK on success; the position advances by the encoded size.
 * @return #TLV_ERR_NULL_ARG if `writer` is `NULL`.
 * @return #TLV_ERR_BUFFER_TOO_SHORT if `pos > capacity` or capacity is insufficient.
 * @return Any error of tlv_copy_element(), propagated unchanged.
 *
 * @note On any failure, including insufficient capacity, the position is
 *       unchanged and the required size is not exposed; use
 *       tlv_element_encoded_size() for that.
 * @see tlv_copy_element
 */
TLV_API tlv_result_t tlv_writer_copy_element(tlv_writer_t* writer, const tlv_element_t* element);

/**
 * @brief Appends an exact encoded byte range at the writer's current position.
 *
 * Copies without framing validation or format conversion, preserving the
 * original wire bytes as tlv_copy_encoded() does. Overlapping byte ranges are
 * supported.
 *
 * As with tlv_writer_copy_element(), a `NULL` writer buffer with zero remaining
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

/**
 * @brief Returns remaining destination capacity without allocating or changing state.
 * @param[in] writer Cursor, or NULL.
 * @return Remaining bytes, or zero for NULL or a position beyond capacity.
 */
TLV_API size_t tlv_writer_remaining(const tlv_writer_t* writer);

/**
 * @brief Appends an Element using the cursor's Format without allocating.
 * @param[in,out] writer Initialized cursor over borrowed caller storage; required.
 * @param[in] element Semantic input; required, not retained and not overlapping output.
 * @return Same as tlv_write_element(); invalid cursor position returns
 *         #TLV_ERR_BUFFER_TOO_SHORT. NULL cursor returns #TLV_ERR_NULL_ARG.
 * @note Advances only on success. No size-query mode. Use tlv_element_encoded_size()
 *       to determine required storage before writing.
 * @warning Callback errors may modify bytes at or beyond the unchanged position.
 */
TLV_API tlv_result_t tlv_writer_write_element(tlv_writer_t* writer, const tlv_element_t* element);

/**
 * @brief Appends an Element with optional structured failure information.
 * @param[in,out] writer Initialized cursor; required.
 * @param[in] element Semantic input as for tlv_writer_write_element().
 * @param[out] diagnostic Optional diagnostic; unchanged on success, absolute output offset.
 * @return Same as tlv_writer_write_element(), with the same state and buffer guarantees.
 */
TLV_API tlv_result_t tlv_writer_write_element_diag(tlv_writer_t* writer,
                                                   const tlv_element_t* element,
                                                   tlv_writer_diagnostic_t* diagnostic);

/**
 * @brief Appends raw encoded bytes with optional structured failure information.
 * @param[in,out] writer Initialized cursor; required.
 * @param[in] encoded_data Raw bytes; NULL only for an empty range. Overlap is supported.
 * @param[in] encoded_length Number of bytes to copy, without framing validation.
 * @param[out] diagnostic Optional diagnostic; unchanged on success, absolute output offset.
 * @return Same as tlv_writer_copy_encoded(); failure leaves position and buffer unchanged.
 */
TLV_API tlv_result_t tlv_writer_copy_encoded_diag(tlv_writer_t* writer, const uint8_t* encoded_data,
                                                  size_t encoded_length,
                                                  tlv_writer_diagnostic_t* diagnostic);

/**
 * @brief Appends unchanged original wire bytes without allocating or re-encoding.
 *
 * Uses tlv_source_preserve() equality checks. The cursor's Format does not
 * convert or validate copied framing. Source and Element descriptors must not
 * overlap destination storage; byte ranges may overlap.
 * @param[in,out] writer Initialized cursor over caller storage; required.
 * @param[in] source Original borrowed Source; its bytes and Format must remain immutable
 *                   and alive through validation/copy, and while Source is subsequently used.
 * @param[in] element Current semantic content; required, must equal original content.
 * @return #TLV_OK on success, #TLV_ERR_BUFFER_TOO_SHORT for insufficient capacity
 *         or invalid position, or an error from tlv_source_preserve().
 * @note Failure leaves position and output bytes unchanged. No size-query mode:
 *       use tlv_source_preserve() with NULL, 0 to measure original representation.
 */
TLV_API tlv_result_t tlv_writer_preserve(tlv_writer_t* writer, const tlv_source_t* source,
                                         const tlv_element_t* element);

/**
 * @brief Preserves original bytes with optional structured failure information.
 * @param[in,out] writer Initialized cursor; required.
 * @param[in] source Immutable borrowed Source as for tlv_writer_preserve().
 * @param[in] element Current semantic content; required.
 * @param[out] diagnostic Optional diagnostic; unchanged on success, absolute output offset.
 * @return Same as tlv_writer_preserve(), with unchanged position and bytes on failure.
 */
TLV_API tlv_result_t tlv_writer_preserve_diag(tlv_writer_t* writer, const tlv_source_t* source,
                                              const tlv_element_t* element,
                                              tlv_writer_diagnostic_t* diagnostic);

#ifdef __cplusplus
}
#endif

/** @} */

#endif /* OPENTLV_WRITER_H */
