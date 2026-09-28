#ifndef OPENTLV_FORMATS_FIXED_H
#define OPENTLV_FORMATS_FIXED_H

#include "tlv/endian.h"
#include "tlv/layout.h"
#include "tlv/export.h"
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file
 * @ingroup formats
 * @brief A configurable fixed-width TLV format: independent tag and length widths,
 * field order and length semantics.
 *
 * Every element is `tag_size` raw tag bytes and a `length_size`-byte length
 * field in `length_order`, in the order `element_order` selects, then the value
 * bytes. Tag bytes are copied unchanged in wire order, so `length_order`
 * applies to the length field only.
 *
 * `length_scope` selects what the length field counts: #TLV_LENGTH_SCOPE_VALUE
 * (the conventional case) counts only the value, so `encoded_length =
 * value_size`; #TLV_LENGTH_SCOPE_TAG_AND_VALUE counts the tag as well, so
 * `encoded_length = tag_size + value_size`. Reading performs the inverse
 * conversion and rejects an encoded length smaller than the non-value portion
 * it must cover with #TLV_ERR_INVALID_LENGTH.
 *
 * A one-byte tag and a one-byte length, the narrowest useful configuration, is
 * `tlv_fixed_format_t{1, 1, TLV_BYTE_ORDER_BIG_ENDIAN}`: the trailing
 * `element_order` and `length_scope` default to #TLV_ELEMENT_ORDER_TLV and
 * #TLV_LENGTH_SCOPE_VALUE respectively, since both are zero-valued
 * enumerators. An application that only ever needs one shape can define it
 * once as a file-scope constant instead of building the format on every use.
 *
 * Bluetooth LTV (tlv/builtins/bluetooth/bluetooth_ltv.h) is this format
 * configured as `{1, 1, TLV_BYTE_ORDER_BIG_ENDIAN, TLV_ELEMENT_ORDER_LTV,
 * TLV_LENGTH_SCOPE_TAG_AND_VALUE}`.
 *
 * @note Writing a tag whose size differs from the configured `tag_size`
 *       returns #TLV_ERR_INVALID_TAG_SIZE.
 */

/** @addtogroup formats
 * @{
 */

/**
 * @brief Fixed format configuration using the generic binary-field layout.
 *
 * @see tlv_binary_layout_t
 */
typedef tlv_binary_layout_t tlv_fixed_format_t;

/**
 * @brief Initializes a format for the configurable fixed-width encoding.
 *
 * Does not allocate. Stores `config`'s address as the format's context: `config`
 * must outlive every reader, writer and operation that uses the initialized
 * format. Both read and write capability are set.
 *
 * @param[out] format Descriptor to initialize.
 * @param[in]  config Fixed-width format state, borrowed. Must not be `NULL`.
 *
 * @return #TLV_OK on success; every field is set.
 * @return #TLV_ERR_INVALID_ARG if `format` or `config` is `NULL`, `config->tag_size`
 *         is 0, `config->length_size` is 0 or greater than 8, or
 *         `config->element_order`/`config->length_scope` is not one of the
 *         enumerators above.
 * @return #TLV_ERR_INVALID_BYTE_ORDER if `config->length_order` is neither
 *         #TLV_BYTE_ORDER_BIG_ENDIAN nor #TLV_BYTE_ORDER_LITTLE_ENDIAN.
 *
 * @note On failure the descriptor is unchanged.
 */
TLV_API tlv_result_t tlv_fixed_format_init(tlv_format_t* format, const tlv_fixed_format_t* config);

#ifdef __cplusplus
}
#endif

/** @} */

#endif
