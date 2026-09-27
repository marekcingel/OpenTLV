#ifndef OPENTLV_FORMATS_FIXED_H
#define OPENTLV_FORMATS_FIXED_H

#include "tlv/endian.h"
#include "tlv/format.h"
#include "tlv/export.h"
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file
 * @ingroup formats
 * @brief A configurable fixed-width TLV format: independent tag and length widths.
 *
 * Every element is `tag_size` raw tag bytes, then a `length_size`-byte length
 * field in `order`, then that many value bytes. The length counts only the
 * value; it excludes the header. Tag bytes are copied unchanged in wire
 * order, so `order` applies to the length field only.
 *
 * A one-byte tag and a one-byte length, the narrowest useful configuration,
 * is `tlv_fixed_format_t{1, 1, TLV_BYTE_ORDER_BIG_ENDIAN}`; an application
 * that only ever needs that shape can define it once as a file-scope
 * constant instead of building the format on every use.
 *
 * @note Writing a tag whose size differs from the configured `tag_size`
 *       returns #TLV_ERR_INVALID_TAG_SIZE.
 */

/** @addtogroup formats
 * @{
 */

/**
 * @brief State describing a configurable fixed-width format.
 *
 * A borrowed, immutable value: the address passed to tlv_fixed_format_init()
 * becomes the initialized format's context, so this state must outlive
 * every reader or writer built from it. It is otherwise an ordinary
 * movable/copyable value; relocating it after tlv_fixed_format_init() changes
 * its address, so re-run tlv_fixed_format_init() against the new address if a
 * format built from the old one is still needed.
 * @see docs/guides/memory.md#format-context-ownership-and-lifetime
 */
typedef struct tlv_fixed_format {
    /** Tag width in bytes; must be at least 1. */
    size_t tag_size;
    /** Length field width in bytes; must be between 1 and 8. */
    size_t length_size;
    /**
     * Byte order of the length field; #TLV_BYTE_ORDER_BIG_ENDIAN or
     * #TLV_BYTE_ORDER_LITTLE_ENDIAN.
     */
    tlv_byte_order_t order;
} tlv_fixed_format_t;

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
 *         is 0, or `config->length_size` is 0 or greater than 8.
 * @return #TLV_ERR_INVALID_BYTE_ORDER if `config->order` is neither
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
