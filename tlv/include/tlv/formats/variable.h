#ifndef OPENTLV_FORMATS_VARIABLE_H
#define OPENTLV_FORMATS_VARIABLE_H

#include "tlv/layout.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file
 * @ingroup formats
 * @brief Configurable variable-width identifier and count primitives.
 *
 * Configurations are immutable and borrowed. No operation allocates. Identifiers
 * retain their complete wire byte identity, including prefix bits; no numeric
 * tag interpretation or minimality rule is imposed. Concrete formats supply
 * their own validity rules. These primitives do not depend on any builtin.
 */

/** @addtogroup formats
 * @{
 */

/**
 * @brief Inline identifier bits with an escape into continuation octets.
 *
 * One octet is sufficient unless `(first & inline_mask) == escape`. In that
 * case at least one continuation octet follows, ending when continuation_bit
 * is clear. Only payload_mask and continuation_bit may be set in those octets.
 * Zero payloads and nonminimal forms are accepted. Bits outside inline_mask
 * in the first octet are preserved without interpretation.
 */
typedef struct tlv_variable_identifier {
    uint8_t inline_mask;      /**< Nonzero mask selecting inline bits in the first octet. */
    uint8_t escape;           /**< Escape pattern, containing only inline_mask bits. */
    uint8_t continuation_bit; /**< Exactly one bit; set means another octet follows. */
    uint8_t payload_mask;     /**< Nonzero payload mask, disjoint from continuation_bit. */
    size_t max_size;          /**< Maximum complete identifier width in bytes; at least one. */
} tlv_variable_identifier_t;

/**
 * @brief Short unsigned count or a prefix specifying the following octet count.
 *
 * When long_form_bit is clear, payload_mask holds the count itself. Otherwise
 * it holds the number of following full octets, interpreted in byte_order.
 * Mask bits are packed from least to most significant, even for noncontiguous
 * masks. Other prefix bits must be zero. A long-form octet count of zero has
 * no definite count and is rejected by this primitive; a concrete format may
 * recognize it in its bounds resolver. No prefix is reserved by a standard.
 * Reading accepts padded and nonminimal counts that fit #tlv_size_t. Writing
 * uses short form when possible, otherwise the fewest full count octets.
 */
typedef struct tlv_variable_length {
    uint8_t long_form_bit;       /**< Exactly one bit selecting long form. */
    uint8_t payload_mask;        /**< Nonzero mask, disjoint from long_form_bit. */
    tlv_byte_order_t byte_order; /**< Order of the full count octets in long form. */
} tlv_variable_length_t;

/**
 * @brief Definite variable-width field configuration for TLV or LTV.
 *
 * Length scope is applied using the actual encoded identifier width. This
 * configuration describes framing only, without constructed or tag semantics.
 */
typedef struct tlv_variable_format {
    tlv_variable_identifier_t identifier; /**< Identifier encoding. */
    tlv_variable_length_t length;         /**< Count encoding. */
    tlv_element_order_t element_order;    /**< Identifier/count field order. */
    tlv_length_scope_t length_scope;      /**< What the encoded count covers. */
} tlv_variable_format_t;

/**
 * @brief Read a complete variable identifier without copying its bytes.
 *
 * @param[in] config Immutable identifier configuration, not NULL.
 * @param[in] data Source bytes; NULL is allowed only when size is zero.
 * @param[in] size Available source bytes.
 * @param[out] tag Identifier borrowing data, which must outlive the result.
 * @param[out] consumed Complete identifier width on success.
 * @return #TLV_OK on success.
 * @return #TLV_ERR_NULL_ARG for a missing required pointer.
 * @return #TLV_ERR_INVALID_ARG for invalid configuration.
 * @return #TLV_ERR_BUFFER_TOO_SHORT for a missing prefix or continuation octet.
 * @return #TLV_ERR_INVALID_TAG_SIZE if the identifier would exceed max_size.
 * @return #TLV_ERR_INVALID_TAG for bits outside the continuation/payload masks.
 * @note Outputs are unchanged on failure. No allocation occurs.
 */
TLV_API tlv_result_t tlv_variable_identifier_read(const tlv_variable_identifier_t* config,
                                                  const uint8_t* data, size_t size, tlv_tag_t* tag,
                                                  size_t* consumed);

/**
 * @brief Validate and copy a raw identifier, or measure it with NULL output.
 *
 * @param[in] config Immutable identifier configuration, not NULL.
 * @param[in] tag Complete raw identifier, not NULL.
 * @param[out] data Destination; NULL with zero capacity queries the width.
 * @param[in] capacity Destination capacity in bytes.
 * @param[out] written Complete identifier width on success.
 * @return #TLV_OK on success.
 * @return #TLV_ERR_NULL_ARG for missing pointers or NULL data with nonzero capacity.
 * @return #TLV_ERR_INVALID_ARG for invalid configuration.
 * @return #TLV_ERR_INVALID_TAG_SIZE for an empty or oversized identifier.
 * @return #TLV_ERR_INVALID_TAG for an incomplete identifier, trailing bytes or invalid bits.
 * @return #TLV_ERR_BUFFER_TOO_SHORT for insufficient destination capacity.
 * @note Outputs are unchanged on failure. Source and destination may overlap.
 */
TLV_API tlv_result_t tlv_variable_identifier_write(const tlv_variable_identifier_t* config,
                                                   const tlv_tag_t* tag, uint8_t* data,
                                                   size_t capacity, size_t* written);

/**
 * @brief Decode a definite count without narrowing to native size.
 *
 * @param[in] config Immutable count configuration, not NULL.
 * @param[in] data Source bytes; NULL is allowed only when size is zero.
 * @param[in] size Available source bytes.
 * @param[out] length Decoded count on success; unchanged on failure.
 * @param[out] consumed Field width on success; available field prefix on wire errors.
 * @return #TLV_OK on success.
 * @return #TLV_ERR_NULL_ARG for a missing required pointer.
 * @return #TLV_ERR_INVALID_ARG for invalid masks.
 * @return #TLV_ERR_INVALID_BYTE_ORDER for unsupported byte order.
 * @return #TLV_ERR_BUFFER_TOO_SHORT for an incomplete field.
 * @return #TLV_ERR_INVALID_LENGTH for invalid prefix bits or zero long-form width.
 * @return #TLV_ERR_OVERFLOW if the complete count exceeds #tlv_size_t.
 * @note Argument/configuration errors leave both outputs unchanged.
 */
TLV_API tlv_result_t tlv_variable_length_read(const tlv_variable_length_t* config,
                                              const uint8_t* data, size_t size, tlv_size_t* length,
                                              size_t* consumed);

/**
 * @brief Encode a definite count, or measure it with NULL output.
 *
 * @param[in] config Immutable count configuration, not NULL.
 * @param[in] length Logical unsigned count.
 * @param[out] data Destination; NULL with zero capacity queries the width.
 * @param[in] capacity Destination capacity in bytes.
 * @param[out] written Encoded count field width on success.
 * @return #TLV_OK on success.
 * @return #TLV_ERR_NULL_ARG for missing pointers or NULL data with nonzero capacity.
 * @return #TLV_ERR_INVALID_ARG for invalid masks.
 * @return #TLV_ERR_INVALID_BYTE_ORDER for unsupported byte order.
 * @return #TLV_ERR_INVALID_LENGTH if the prefix cannot represent the required width.
 * @return #TLV_ERR_BUFFER_TOO_SHORT for insufficient destination capacity.
 * @note Outputs are unchanged on failure. No allocation occurs.
 */
TLV_API tlv_result_t tlv_variable_length_write(const tlv_variable_length_t* config,
                                               tlv_size_t length, uint8_t* data, size_t capacity,
                                               size_t* written);

/**
 * @brief Initialize reusable variable field callbacks for format composition.
 *
 * @param[out] fields Field composition, unchanged on failure.
 * @param[in] config Immutable configuration, borrowed; must outlive fields and its users.
 * @return #TLV_OK on success.
 * @return #TLV_ERR_NULL_ARG for NULL fields or config.
 * @return #TLV_ERR_INVALID_ARG for invalid masks, widths, ordering or scope.
 * @return #TLV_ERR_INVALID_BYTE_ORDER for unsupported length byte order.
 * @note No allocation occurs. The resulting context points to config. A concrete
 * format may add a #tlv_resolve_bounds_fn for terminated TLV/VALUE framing;
 * it must provide matching canonical measure/encode callbacks to write trailers.
 * Standalone primitives also support compositions with a caller-defined context.
 */
TLV_API tlv_result_t tlv_variable_fields_init(tlv_field_layout_t* fields,
                                              const tlv_variable_format_t* config);

/**
 * @brief Initialize a bidirectional definite variable-width format.
 *
 * @param[out] format Descriptor, unchanged on failure.
 * @param[in] config Immutable configuration, borrowed; must outlive format and its users.
 * @return #TLV_OK on success.
 * @return #TLV_ERR_NULL_ARG for NULL format or config.
 * @return #TLV_ERR_INVALID_ARG for invalid masks, widths, ordering or scope.
 * @return #TLV_ERR_INVALID_BYTE_ORDER for unsupported length byte order.
 * @note No allocation occurs. The descriptor borrows config directly and can be
 * copied. No runtime engine or builtin is required.
 */
TLV_API tlv_result_t tlv_variable_format_init(tlv_format_t* format,
                                              const tlv_variable_format_t* config);

/** @} */

#ifdef __cplusplus
}
#endif
#endif
