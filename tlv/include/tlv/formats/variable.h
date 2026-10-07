// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#ifndef OPENTLV_FORMATS_VARIABLE_H
#define OPENTLV_FORMATS_VARIABLE_H

#include "tlv/formats/compose.h"
#include "tlv/field/variable.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file
 * @ingroup formats
 * @brief Format composition of variable-width identifier and count encodings.
 *
 * Configurations are immutable and borrowed. Field Encoding primitives are
 * declared in tlv/field/variable.h; this API supplies ordering and count scope.
 */

/** @addtogroup formats
 * @{
 */

/**
 * @brief Definite variable-width field configuration for TLV or LTV.
 *
 * Length scope is applied using the actual encoded identifier width. This
 * configuration describes framing and optional byte-based constructed classification.
 * All policies and predicate storage are borrowed, immutable and must outlive users.
 */
typedef struct tlv_variable_format {
    tlv_variable_identifier_t identifier;     /**< Identifier encoding. */
    tlv_variable_length_t length;             /**< Count encoding. */
    tlv_element_order_t element_order;        /**< Identifier/count field order. */
    tlv_length_scope_t length_scope;          /**< What the encoded count covers. */
    const tlv_constructed_bit_t* constructed; /**< Optional borrowed Tag bit predicate. */
} tlv_variable_format_t;

/**
 * @brief Decode configured variable fields.
 * @copydetails tlv_decode_fn
 * @note context must point to a valid immutable tlv_variable_format_t.
 */
TLV_API tlv_result_t tlv_variable_decode(const void* context, const uint8_t* data, size_t size,
                                         tlv_decoded_t* result, tlv_format_error_t* error);

/**
 * @brief Measure configured variable fields.
 * @copydetails tlv_measure_fn
 * @note context must point to a valid immutable tlv_variable_format_t.
 */
TLV_API tlv_result_t tlv_variable_measure(const void* context, const tlv_element_t* element,
                                          tlv_encoding_t* encoding, tlv_format_error_t* error);

/**
 * @brief Encode configured variable fields.
 * @copydetails tlv_encode_fn
 * @note context must point to a valid immutable tlv_variable_format_t.
 */
TLV_API tlv_result_t tlv_variable_encode(const void* context, const tlv_element_t* element,
                                         uint8_t* data, size_t capacity, size_t* written,
                                         tlv_format_error_t* error);

/**
 * @brief Apply a variable Format's optional constructed predicate.
 * @param[in] context Borrowed tlv_variable_format_t; NULL means no match.
 * @param[in] tag Borrowed canonical Tag; NULL means no match.
 * @return The result of tlv_constructed_bit_predicate(), or zero without a predicate.
 * @note No allocation or mutation; policies are not identifier validators here.
 */
TLV_API int tlv_variable_is_constructed(const void* context, const tlv_tag_t* tag);

/**
 * @brief Initialize reusable variable field callbacks for format composition.
 *
 * @param[out] fields Field composition, unchanged on failure.
 * @param[in] config Immutable configuration, borrowed; must outlive fields and its users.
 * @return #TLV_OK on success.
 * @return #TLV_ERR_NULL_ARG for NULL fields or config.
 * @return #TLV_ERR_INVALID_ARG for invalid masks, widths, policies, predicate, ordering or scope.
 * @return #TLV_ERR_INVALID_BYTE_ORDER for unsupported length byte order.
 * @note No allocation occurs. The resulting context points to config. A concrete
 * format may add a #tlv_resolve_bounds_fn for terminated TLV/VALUE framing;
 * it must provide matching canonical measure/encode callbacks to write trailers.
 * Standalone primitives also support compositions with a caller-defined context.
 */
TLV_API tlv_result_t tlv_variable_fields_init(tlv_field_composition_t* fields,
                                              const tlv_variable_format_t* config);

/**
 * @brief Initialize a bidirectional definite variable-width format.
 *
 * @param[out] format Descriptor, unchanged on failure.
 * @param[in] config Immutable configuration, borrowed; must outlive format and its users.
 * @return #TLV_OK on success.
 * @return #TLV_ERR_NULL_ARG for NULL format or config.
 * @return #TLV_ERR_INVALID_ARG for invalid masks, widths, policies, predicate, ordering or scope.
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
