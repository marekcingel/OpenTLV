#ifndef OPENTLV_CER_H
#define OPENTLV_CER_H

#include "tlv/error.h"
#include "tlv/formats/asn1/cer.h"
#include "tlv/reader/walker.h"
#include "tlv/export.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file
 * @ingroup profiles
 * @brief Bounded recursive CER validation, traversal and canonical writing.
 *
 * All functions here are allocation-free and use no C recursion. All limits
 * are inclusive, and zero is a real limit. Passing `NULL` limits selects
 * #tlv_cer_default_limits.
 */

/** @addtogroup profiles
 * @{
 */

/**
 * @brief Maximum content octets of a single CER string segment (ITU-T X.690 section 9.2).
 *
 * Also the primitive/constructed threshold for the segmentable UNIVERSAL
 * types (BIT STRING, OCTET STRING, and the restricted character string types
 * including UTF8String): a value with this many content octets or fewer must
 * be primitive; a longer one must be constructed and segmented.
 */
enum { TLV_CER_MAX_SEGMENT_OCTETS = 1000 };

/** @brief Maximum `max_depth` accepted in #tlv_cer_limits_t. */
enum { TLV_CER_MAX_DEPTH = 64 };

/**
 * @brief Inclusive resource limits for CER validation and writing.
 *
 * Top-level elements have depth 0. All limits are inclusive; zero is a real
 * limit.
 */
typedef struct tlv_cer_limits {
    /** Maximum number of constructed ancestors, `0..TLV_CER_MAX_DEPTH`. */
    size_t max_depth;
    /** Bounds the supplied input, or the complete encoded output when writing. */
    size_t max_input_size;
    /**
     * Bounds each element's content: a constructed element's assembled
     * indefinite content, or a segmented value's logical content, not
     * per-segment framing overhead.
     */
    size_t max_value_size;
    /** Bounds the total visited elements, including each string segment. */
    size_t max_elements;
} tlv_cer_limits_t;

/** @brief Default limits used when a function receives `NULL` limits. */
extern TLV_API const tlv_cer_limits_t tlv_cer_default_limits;

/**
 * @brief Callback for zero-copy CER traversal.
 *
 * `view` is temporary and its value borrows the input, excluding the
 * element's own EOC for a constructed element (consistent with the
 * framing-exclusion convention of tlv_read()). A constructed string's
 * segments are ordinary primitive children one level deeper; to access them
 * zero-copy, iterate the constructed string element's own borrowed value
 * (`view->value`), for example with
 * `tlv_walk(view->value.data, size, &tlv_reader_format_cer, ...)`. See
 * docs/profiles/cer/README.md.
 *
 * Unlike #tlv_der_visitor_t's preorder guarantee, CER traversal is postorder
 * for constructed elements: a primitive element (including each string
 * segment) is visited immediately when read, but a constructed element, whose
 * indefinite length is not known until its matching EOC is found, is visited
 * only after all of its descendants. This deliberate difference from DER,
 * required by indefinite framing, keeps traversal a single linear pass with
 * no rescanning.
 *
 * @param view    Current element; temporary.
 * @param depth   Number of constructed ancestors; top-level elements have depth 0.
 * @param offset  Absolute input offset of the element's tag.
 * @param context Caller context passed to tlv_cer_walk().
 *
 * @return A #tlv_visit_result_t controlling traversal.
 *
 * @warning Callback side effects are not rolled back on errors.
 */
typedef tlv_visit_result_t (*tlv_cer_visitor_t)(const tlv_view_t* view, size_t depth, size_t offset,
                                                void* context);

/**
 * @brief Validates one complete CER element, including all descendants.
 *
 * Checks indefinite constructed framing, EOC placement and canonical string
 * segmentation, but not universal content semantics (see
 * tlv_cer_read_strict()). Trailing bytes after the element are ignored, but
 * `max_input_size` covers `size`.
 *
 * @param[in]  data         Encoded input.
 * @param[in]  size         Input size in bytes.
 * @param[in]  limits       Limits, or `NULL` for #tlv_cer_default_limits.
 * @param[out] view         Receives the element; its value borrows `data`.
 * @param[out] consumed     Receives the encoded size of the element.
 * @param[out] error_offset Optional. On failure receives the start of the
 *                          failing tag, length, value or (missing, truncated
 *                          or unexpected) EOC field; nested and per-segment
 *                          offsets are relative to `data`. Argument and
 *                          input-limit errors use 0. Unchanged on success.
 *
 * @return #TLV_OK on success.
 * @return #TLV_ERR_END_OF_BUFFER for empty input.
 * @return #TLV_ERR_LIMIT if a limit is exceeded.
 * @return Another error code for malformed or noncanonical input.
 *
 * @note Outputs other than `error_offset` remain unchanged on failure.
 * @warning The caller must keep `data` alive while `view` is used.
 */
TLV_API tlv_result_t tlv_cer_read(const uint8_t* data, size_t size, const tlv_cer_limits_t* limits,
                                  tlv_view_t* view, size_t* consumed, size_t* error_offset);

/**
 * @brief Validates all concatenated CER elements recursively.
 *
 * Empty input succeeds. Uses the same offset, limit and visit-order
 * conventions as tlv_cer_read() and #tlv_cer_visitor_t.
 *
 * @param[in]  data         Encoded input.
 * @param[in]  size         Input size in bytes.
 * @param[in]  limits       Limits, or `NULL` for #tlv_cer_default_limits.
 * @param[in]  visitor      Callback per element; `NULL` validates only.
 * @param[in]  context      Passed to the visitor unchanged.
 * @param[out] error_offset Optional; see tlv_cer_read().
 *
 * @return #TLV_OK on success, including a visitor stop.
 * @return #TLV_ERR_VISITOR if the visitor requests an error stop.
 * @return Any error of tlv_cer_read().
 *
 * @warning Callback side effects are not rolled back on errors.
 */
TLV_API tlv_result_t tlv_cer_walk(const uint8_t* data, size_t size, const tlv_cer_limits_t* limits,
                                  tlv_cer_visitor_t visitor, void* context, size_t* error_offset);

/**
 * @brief Writes a canonical CER element.
 *
 * Writes canonical tag, length and EOC framing. For a constructed tag,
 * `value` is pre-encoded child bytes without the enclosing EOC, which is
 * added automatically; the children are validated recursively as canonical
 * CER framing (and canonical segmentation) before writing. For a primitive
 * tag, `value` is raw content, written with a canonical minimal definite
 * length.
 *
 * Primitive content longer than #TLV_CER_MAX_SEGMENT_OCTETS for a
 * segmentable UNIVERSAL type is always rejected, even by the non-strict
 * function, because it is a structural rule. Use
 * tlv_cer_write_segmented_string() to encode logical string content of any
 * length.
 *
 * @param[out] data         Destination. `NULL` with zero `capacity` queries the
 *                          size, including validation.
 * @param[in]  capacity     Destination capacity in bytes.
 * @param[in]  tag          Element tag.
 * @param[in]  value        Value bytes; must not overlap the destination.
 * @param[in]  length       Value length in bytes.
 * @param[in]  limits       Limits, or `NULL` for #tlv_cer_default_limits.
 * @param[out] written      Receives the encoded (or required) size.
 * @param[out] error_offset Optional. Offset of the failure relative to the
 *                          would-be output, using the read conventions.
 *
 * @return #TLV_OK on success.
 * @return #TLV_ERR_BUFFER_TOO_SHORT if `capacity` is insufficient.
 * @return Another error code for invalid arguments, tags, lengths or children.
 *
 * @note Output and `*written` remain unchanged on error.
 */
TLV_API tlv_result_t tlv_cer_write(uint8_t* data, size_t capacity, tlv_tag_t tag,
                                   const uint8_t* value, size_t length,
                                   const tlv_cer_limits_t* limits, size_t* written,
                                   size_t* error_offset);

/**
 * @brief Strict counterpart of tlv_cer_read().
 *
 * Identical contract, offsets and limits, but every UNIVERSAL-class element
 * it encounters (including nested ones) also has its content validated
 * against ASN.1 CER canonical rules. For a segmentable constructed value
 * this includes every string segment, validated per segment as it is
 * encountered without ever concatenating them. Non-UNIVERSAL values are
 * unaffected, matching the non-strict function.
 *
 * @return #TLV_ERR_INVALID_VALUE for a recognized type with invalid or
 *         noncanonical content.
 * @return #TLV_ERR_UNSUPPORTED_TYPE for a universal type without an
 *         implemented canonical rule, including constructed ones.
 * @return Otherwise any result of tlv_cer_read().
 *
 * @see docs/profiles/cer/README.md for the supported-type table.
 */
TLV_API tlv_result_t tlv_cer_read_strict(const uint8_t* data, size_t size,
                                         const tlv_cer_limits_t* limits, tlv_view_t* view,
                                         size_t* consumed, size_t* error_offset);
/**
 * @brief Strict counterpart of tlv_cer_walk().
 *
 * Adds the content validation described for tlv_cer_read_strict().
 *
 * @see tlv_cer_read_strict
 */
TLV_API tlv_result_t tlv_cer_walk_strict(const uint8_t* data, size_t size,
                                         const tlv_cer_limits_t* limits, tlv_cer_visitor_t visitor,
                                         void* context, size_t* error_offset);
/**
 * @brief Strict counterpart of tlv_cer_write().
 *
 * Adds the content validation described for tlv_cer_read_strict(), including
 * for the top-level element given here.
 *
 * @see tlv_cer_read_strict
 */
TLV_API tlv_result_t tlv_cer_write_strict(uint8_t* data, size_t capacity, tlv_tag_t tag,
                                          const uint8_t* value, size_t length,
                                          const tlv_cer_limits_t* limits, size_t* written,
                                          size_t* error_offset);

/**
 * @brief Encodes logical string content as canonical CER.
 *
 * Takes logical string content, not pre-encoded segments, for a
 * primitive-form UNIVERSAL string tag (OCTET STRING, BIT STRING, or a
 * supported restricted character string or UTF8String type). Emits a single
 * primitive element when `content_length` is at most
 * #TLV_CER_MAX_SEGMENT_OCTETS, otherwise a constructed indefinite element
 * with 1000-octet non-final segments and a correctly sized final segment
 * (never an unnecessary trailing empty segment on an exact multiple of
 * 1000).
 *
 * For BIT STRING, `content[0]` is the unused-bits count (0-7) and the
 * remaining bytes are bit octets, matching the whole-value convention used
 * elsewhere in this library; `content_length` includes that leading octet.
 *
 * Contents are always validated against the type's canonical rule before
 * writing. There is no non-strict variant: unlike tlv_cer_write(), which
 * passes pre-encoded bytes through, this function exists to produce correct
 * canonical output from logical content. Size arithmetic, including every
 * segment header and the EOC, is overflow-checked before writing.
 *
 * @param[out] data           Destination. `NULL` with zero `capacity` queries the
 *                            size, including validation.
 * @param[in]  capacity       Destination capacity in bytes.
 * @param[in]  tag            A primitive-form UNIVERSAL tag for a segmentable type.
 * @param[in]  content        Logical content bytes.
 * @param[in]  content_length Content length in bytes.
 * @param[in]  limits         Limits, or `NULL` for #tlv_cer_default_limits.
 * @param[out] written        Receives the encoded (or required) size.
 * @param[out] error_offset   Optional. Offset of the failure, using
 *                            tlv_cer_write()'s would-be-output-relative
 *                            conventions.
 *
 * @return #TLV_OK on success.
 * @return #TLV_ERR_INVALID_ARG if `tag` is not a primitive-form UNIVERSAL
 *         tag for a segmentable type.
 * @return #TLV_ERR_INVALID_VALUE if the content fails the type's canonical rule.
 * @return #TLV_ERR_BUFFER_TOO_SHORT if `capacity` is insufficient.
 * @return Another error code for invalid arguments or limits.
 *
 * @note Failed calls leave `data` and `*written` unchanged.
 */
TLV_API tlv_result_t tlv_cer_write_segmented_string(uint8_t* data, size_t capacity, tlv_tag_t tag,
                                                    const uint8_t* content, size_t content_length,
                                                    const tlv_cer_limits_t* limits, size_t* written,
                                                    size_t* error_offset);

#ifdef __cplusplus
}
#endif
/** @} */

#endif /* OPENTLV_CER_H */
