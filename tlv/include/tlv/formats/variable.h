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
 * configuration describes framing only, without constructed or tag semantics.
 */
typedef struct tlv_variable_format {
    tlv_variable_identifier_t identifier; /**< Identifier encoding. */
    tlv_variable_length_t length;         /**< Count encoding. */
    tlv_element_order_t element_order;    /**< Identifier/count field order. */
    tlv_length_scope_t length_scope;      /**< What the encoded count covers. */
} tlv_variable_format_t;

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
TLV_API tlv_result_t tlv_variable_fields_init(tlv_field_composition_t* fields,
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
