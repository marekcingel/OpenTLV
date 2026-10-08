// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel
#ifndef OPENTLV_READER_DIAGNOSTIC_H
#define OPENTLV_READER_DIAGNOSTIC_H
#include "tlv/diagnostic.h"
#include "tlv/size.h"
#include "tlv/format.h"
/**
 * @file
 * @ingroup reader
 * @brief Reader diagnostic vocabulary usable without the Reader implementation.
 */
/**
 * @brief Which parsing step a #tlv_reader_diagnostic_t reports on.
 */
typedef enum tlv_reader_operation {
    /** Decoding the tag. */
    TLV_READER_OP_TAG = 0,
    /** Decoding the length field, or the header for a whole-element format. */
    TLV_READER_OP_LENGTH,
    /** Checking the value against the bytes available or an enclosing boundary. */
    TLV_READER_OP_VALUE,
    /** Checking trailing framing, such as a BER end-of-contents marker. */
    TLV_READER_OP_TRAILER,
    /** An unnamed header field or complete header. */
    TLV_READER_OP_HEADER
} tlv_reader_operation_t;

/**
 * @brief Structured detail for a failed tlv_read() or tlv_reader_next() call.
 *
 * Pairs a #tlv_diagnostic_t with the reader-specific state needed to locate a
 * parsing failure precisely: which step failed, the tag being processed if
 * one was already decoded, the offsets of the fields involved, and the sizes
 * that made the operation fail. Every field is a fixed-size value or a
 * borrowed pointer, so filling one never allocates. Diagnostic `tag` borrows
 * the raw wire envelope reported in the format error; for transformed
 * identifiers this is not the canonical semantic Tag.
 *
 * A field not applicable to the failure that produced the diagnostic is left
 * unset, indicated by its paired `has_*` flag being zero.
 *
 * Once initialized by an operation, a non-#TLV_OK return has the same code in
 * `diagnostic.code`. Preflight checks which run before initialization leave
 * this object untouched. A successful call need not clear earlier detail.
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
    tlv_size_t declared_length;
    /** Nonzero if raw length-field bytes are available, even for a failed decode. */
    int has_raw_length;
    /**
     * Borrowed original length bytes (or the available prefix when truncated).
     * Valid only when `has_raw_length` is nonzero. The source buffer must
     * remain valid and unchanged while this diagnostic is used.
     */
    tlv_length_t raw_length;
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
    /** Nonzero when Format knows the required extent of the failing region. */
    int has_required;
    /** Required region size in bytes, not an absolute offset or an additional byte count. */
    tlv_size_t required;
} tlv_reader_diagnostic_t;
#endif
