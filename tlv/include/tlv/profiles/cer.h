#ifndef OPENTLV_CER_H
#define OPENTLV_CER_H

#include "tlv/formats/asn1/cer.h"
#include "tlv/reader/walker.h"
#include "tlv/export.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Maximum content octets of a single CER string segment (ITU-T X.690 §9.2);
 * also the primitive/constructed threshold for the segmentable UNIVERSAL
 * types (BIT STRING, OCTET STRING, and the restricted character string
 * types including UTF8String): a value with this many content octets or
 * fewer must be primitive, more must be constructed and segmented.
 */
enum { TLV_CER_MAX_SEGMENT_OCTETS = 1000 };

/* Maximum number of constructed ancestors; top-level elements have depth 0.
 * max_depth may be 0 through TLV_CER_MAX_DEPTH. All limits are inclusive;
 * zero is a real limit. NULL limits selects tlv_cer_default_limits.
 * max_input_size bounds supplied input / complete encoded output,
 * max_value_size bounds each element's content (a constructed element's
 * assembled indefinite content, or a segmented value's logical content, not
 * per-segment framing overhead), and max_elements bounds total visited
 * elements, including each string segment.
 */
enum { TLV_CER_MAX_DEPTH = 64 };
typedef struct tlv_cer_limits {
    size_t max_depth;
    size_t max_input_size;
    size_t max_value_size;
    size_t max_elements;
} tlv_cer_limits_t;
extern TLV_API const tlv_cer_limits_t tlv_cer_default_limits;

/* Zero-copy traversal callback. offset is the element's absolute tag offset;
 * depth counts constructed ancestors (top-level is zero). view is
 * temporary; its value borrows input, excluding the element's own EOC for a
 * constructed element (consistent with tlv_read's framing-exclusion
 * convention). A constructed string's segments are ordinary primitive
 * children one level deeper; iterate a constructed string element's own
 * borrowed value (view.value) for zero-copy segment access, e.g. with
 * tlv_walk(view.value.data, size, &tlv_reader_format_cer, ...) -- see
 * docs/profiles/cer/README.md.
 *
 * Unlike tlv_der_visitor_t's preorder guarantee, CER traversal is postorder
 * for constructed elements: a primitive element (including each string
 * segment) is visited immediately when read, but a constructed element --
 * whose indefinite length is not known until its matching EOC is found -- is
 * visited only after all of its descendants, once its true span is known.
 * This is a deliberate difference from DER, required by indefinite framing,
 * that keeps traversal a single linear pass with no rescanning. Callback
 * side effects are not rolled back on errors.
 */
typedef tlv_visit_result_t (*tlv_cer_visitor_t)(const tlv_view_t* view, size_t depth, size_t offset,
                                                void* context);

/* Validates one complete element, including all descendants, indefinite
 * constructed framing, EOC placement and canonical string segmentation
 * (but not universal content semantics -- see tlv_cer_read_strict);
 * ignores trailing bytes (but max_input_size covers size). Empty input
 * returns TLV_ERR_END_OF_BUFFER. Outputs remain unchanged on failure, except
 * optional error_offset, which receives the start of the failing tag,
 * length, value or (missing/truncated/unexpected) EOC field. Nested and
 * per-segment offsets are relative to data. Argument/input-limit errors use
 * 0. Success leaves it unchanged. No allocations and no C recursion.
 */
TLV_API tlv_result_t tlv_cer_read(const uint8_t* data, size_t size, const tlv_cer_limits_t* limits,
                                  tlv_view_t* view, size_t* consumed, size_t* error_offset);

/* Validates all concatenated elements recursively; empty input succeeds.
 * visitor may be NULL for validation only. Same offset, limit and visit
 * order conventions as above.
 */
TLV_API tlv_result_t tlv_cer_walk(const uint8_t* data, size_t size, const tlv_cer_limits_t* limits,
                                  tlv_cer_visitor_t visitor, void* context, size_t* error_offset);

/* Writes canonical CER tag/length/EOC framing. For a constructed tag, value
 * is pre-encoded child bytes without the enclosing EOC (added automatically);
 * they are validated recursively as canonical CER framing (and canonical
 * segmentation) before writing. For a primitive tag, value is raw content,
 * written with a canonical minimal definite length. Primitive content
 * longer than TLV_CER_MAX_SEGMENT_OCTETS for a segmentable UNIVERSAL type is
 * always rejected (a structural rule, checked even here in the non-strict
 * function) -- use tlv_cer_write_segmented_string() to encode logical
 * string content of any length. NULL data with zero capacity queries size,
 * including validation. Value and destination must not overlap. Output and
 * written remain unchanged on error. error_offset is relative to the
 * would-be output, using read conventions.
 */
TLV_API tlv_result_t tlv_cer_write(uint8_t* data, size_t capacity, tlv_tag_t tag,
                                   const uint8_t* value, size_t length,
                                   const tlv_cer_limits_t* limits, size_t* written,
                                   size_t* error_offset);

/* Strict counterparts of tlv_cer_read/tlv_cer_walk/tlv_cer_write: identical
 * contracts, offsets and limits, but every UNIVERSAL-class element they
 * encounter (including nested ones, and the top-level element given to
 * tlv_cer_write_strict) additionally has its content validated against
 * ASN.1 CER canonical rules -- including, for a segmentable constructed
 * value, every string segment (validated per segment as it is encountered,
 * without ever concatenating them). Recognized types with invalid or
 * noncanonical content return TLV_ERR_INVALID_VALUE; universal types
 * without an implemented canonical rule return TLV_ERR_UNSUPPORTED_TYPE,
 * including constructed ones. See docs/profiles/cer/README.md for the
 * supported-type table. Non-UNIVERSAL values are unaffected, matching the
 * non-strict functions.
 */
TLV_API tlv_result_t tlv_cer_read_strict(const uint8_t* data, size_t size,
                                         const tlv_cer_limits_t* limits, tlv_view_t* view,
                                         size_t* consumed, size_t* error_offset);
TLV_API tlv_result_t tlv_cer_walk_strict(const uint8_t* data, size_t size,
                                         const tlv_cer_limits_t* limits, tlv_cer_visitor_t visitor,
                                         void* context, size_t* error_offset);
TLV_API tlv_result_t tlv_cer_write_strict(uint8_t* data, size_t capacity, tlv_tag_t tag,
                                          const uint8_t* value, size_t length,
                                          const tlv_cer_limits_t* limits, size_t* written,
                                          size_t* error_offset);

/* Encodes logical string content -- not pre-encoded segments -- for a
 * primitive-form UNIVERSAL string tag (OCTET STRING, BIT STRING, or a
 * supported restricted character string / UTF8String type) as canonical
 * CER: a single primitive element when content_length is at most
 * TLV_CER_MAX_SEGMENT_OCTETS, otherwise a constructed indefinite element
 * with 1000-octet non-final segments and a correctly-sized final segment
 * (never an unnecessary trailing empty segment on an exact multiple of
 * 1000). For BIT STRING, content[0] is the unused-bits count (0-7) and the
 * remaining bytes are bit octets, matching the whole-value convention used
 * elsewhere in this library; content_length includes that leading octet.
 *
 * Contents are always validated against the type's canonical rule before
 * writing (there is no non-strict variant of this function: unlike
 * tlv_cer_write, which passes pre-encoded bytes through, this function
 * exists specifically to produce correct canonical output from logical
 * content). tag must be a primitive-form UNIVERSAL tag for a segmentable
 * type (TLV_ERR_INVALID_ARG otherwise). NULL data with zero capacity
 * queries size, including validation. Failed calls leave data and written
 * unchanged; error_offset uses tlv_cer_write's would-be-output-relative
 * conventions. Allocation-free; size arithmetic (including every segment
 * header and the EOC) is overflow-checked before writing.
 */
TLV_API tlv_result_t tlv_cer_write_segmented_string(uint8_t* data, size_t capacity, tlv_tag_t tag,
                                                    const uint8_t* content, size_t content_length,
                                                    const tlv_cer_limits_t* limits, size_t* written,
                                                    size_t* error_offset);

#ifdef __cplusplus
}
#endif
#endif /* OPENTLV_CER_H */
