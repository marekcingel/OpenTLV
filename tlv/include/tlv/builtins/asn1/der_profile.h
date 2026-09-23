#ifndef OPENTLV_BUILTINS_ASN1_DER_PROFILE_H
#define OPENTLV_BUILTINS_ASN1_DER_PROFILE_H

#include "tlv/error.h"
#include "tlv/builtins/asn1/der.h"
#include "tlv/reader/walker.h"
#include "tlv/export.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file
 * @ingroup profiles
 * @brief Bounded recursive DER validation, traversal and canonical writing.
 *
 * All functions here are allocation-free and use no C recursion. All limits
 * are inclusive, and zero is a real limit. Passing `NULL` limits selects
 * #tlv_der_default_limits.
 */

/** @addtogroup profiles
 * @{
 */

/** @brief Maximum `max_depth` accepted in #tlv_der_limits_t. */
enum { TLV_DER_MAX_DEPTH = 64 };

/**
 * @brief Inclusive resource limits for DER validation and writing.
 *
 * Top-level elements have depth 0. All limits are inclusive; zero is a real
 * limit.
 */
typedef struct tlv_der_limits {
    /** Maximum number of constructed ancestors, `0..TLV_DER_MAX_DEPTH`. */
    size_t max_depth;
    /** Bounds the supplied input, or the complete encoded output when writing. */
    size_t max_input_size;
    /** Bounds each value. */
    size_t max_value_size;
    /** Bounds the total visited elements. */
    size_t max_elements;
} tlv_der_limits_t;

/** @brief Default limits used when a function receives `NULL` limits. */
extern TLV_API const tlv_der_limits_t tlv_der_default_limits;

/**
 * @brief Callback for zero-copy preorder DER traversal.
 *
 * @param view    Current element; temporary, its value borrows the input.
 * @param depth   Number of constructed ancestors; top-level elements have depth 0.
 * @param offset  Absolute input offset of the element's tag.
 * @param context Caller context passed to tlv_der_walk().
 *
 * @return A #tlv_visit_result_t. #TLV_VISIT_STOP succeeds without validating
 *         the rest of the input.
 *
 * @warning Callback side effects are not rolled back on errors.
 */
typedef tlv_visit_result_t (*tlv_der_visitor_t)(const tlv_view_t* view, size_t depth, size_t offset,
                                                void* context);

/**
 * @brief Validates one complete DER element, including all descendants.
 *
 * Trailing bytes after the element are ignored, but `max_input_size` covers
 * `size`.
 *
 * @param[in]  data         Encoded input.
 * @param[in]  size         Input size in bytes.
 * @param[in]  limits       Limits, or `NULL` for #tlv_der_default_limits.
 * @param[out] view         Receives the element; its value borrows `data`.
 * @param[out] consumed     Receives the encoded size of the element.
 * @param[out] error_offset Optional. On failure receives the start of the
 *                          failing tag, length, or value field, relative to
 *                          `data`; argument and input-limit errors use 0.
 *                          Unchanged on success.
 *
 * @return #TLV_OK on success.
 * @return #TLV_ERR_END_OF_BUFFER for empty input.
 * @return #TLV_ERR_LIMIT if a limit is exceeded.
 * @return Another error code for malformed or noncanonical input.
 *
 * @note Outputs other than `error_offset` remain unchanged on failure.
 * @warning The caller must keep `data` alive while `view` is used.
 */
TLV_API tlv_result_t tlv_der_read(const uint8_t* data, size_t size, const tlv_der_limits_t* limits,
                                  tlv_view_t* view, size_t* consumed, size_t* error_offset);

/**
 * @brief Validates all concatenated DER elements recursively.
 *
 * Empty input succeeds. Uses the same offset and limit conventions as
 * tlv_der_read().
 *
 * @param[in]  data         Encoded input.
 * @param[in]  size         Input size in bytes.
 * @param[in]  limits       Limits, or `NULL` for #tlv_der_default_limits.
 * @param[in]  visitor      Callback per element in preorder; `NULL` validates only.
 * @param[in]  context      Passed to the visitor unchanged.
 * @param[out] error_offset Optional; see tlv_der_read().
 *
 * @return #TLV_OK on success, including a visitor stop.
 * @return #TLV_ERR_VISITOR if the visitor requests an error stop.
 * @return Any error of tlv_der_read().
 *
 * @warning Callback side effects are not rolled back on errors.
 */
TLV_API tlv_result_t tlv_der_walk(const uint8_t* data, size_t size, const tlv_der_limits_t* limits,
                                  tlv_der_visitor_t visitor, void* context, size_t* error_offset);

/**
 * @brief Writes a canonical DER element.
 *
 * Writes canonical tag and length bytes and copies the value verbatim.
 * Constructed values must already contain canonical DER-TLV children, which
 * are validated first. No ASN.1 value semantics or SET/SET OF ordering
 * validation is performed.
 *
 * @param[out] data         Destination. `NULL` with zero `capacity` queries the
 *                          size, including validation.
 * @param[in]  capacity     Destination capacity in bytes.
 * @param[in]  tag          Element tag.
 * @param[in]  value        Value bytes; must not overlap the destination.
 * @param[in]  length       Value length in bytes.
 * @param[in]  limits       Limits, or `NULL` for #tlv_der_default_limits.
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
TLV_API tlv_result_t tlv_der_write(uint8_t* data, size_t capacity, tlv_tag_t tag,
                                   const uint8_t* value, size_t length,
                                   const tlv_der_limits_t* limits, size_t* written,
                                   size_t* error_offset);

/**
 * @brief Strict counterpart of tlv_der_read().
 *
 * Identical contract, offsets and limits, but every UNIVERSAL-class
 * primitive element (including nested ones) also has its content validated
 * against ASN.1 DER canonical rules. Non-UNIVERSAL and constructed values
 * are unaffected, matching the non-strict function.
 *
 * @return #TLV_ERR_INVALID_VALUE for a recognized universal type with
 *         invalid or noncanonical content.
 * @return #TLV_ERR_UNSUPPORTED_TYPE for a universal type without an
 *         implemented canonical rule.
 * @return Otherwise any result of tlv_der_read().
 *
 * @see docs/profiles/der/README.md for the supported-type table.
 */
TLV_API tlv_result_t tlv_der_read_strict(const uint8_t* data, size_t size,
                                         const tlv_der_limits_t* limits, tlv_view_t* view,
                                         size_t* consumed, size_t* error_offset);
/**
 * @brief Strict counterpart of tlv_der_walk().
 *
 * Adds the content validation described for tlv_der_read_strict().
 *
 * @see tlv_der_read_strict
 */
TLV_API tlv_result_t tlv_der_walk_strict(const uint8_t* data, size_t size,
                                         const tlv_der_limits_t* limits, tlv_der_visitor_t visitor,
                                         void* context, size_t* error_offset);
/**
 * @brief Strict counterpart of tlv_der_write().
 *
 * Adds the content validation described for tlv_der_read_strict().
 *
 * @see tlv_der_read_strict
 */
TLV_API tlv_result_t tlv_der_write_strict(uint8_t* data, size_t capacity, tlv_tag_t tag,
                                          const uint8_t* value, size_t length,
                                          const tlv_der_limits_t* limits, size_t* written,
                                          size_t* error_offset);

#ifdef __cplusplus
}
#endif
/** @} */

#endif /* OPENTLV_BUILTINS_ASN1_DER_PROFILE_H */
