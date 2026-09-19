#ifndef OPENTLV_FORMATS_FIXED_1BYTE_H
#define OPENTLV_FORMATS_FIXED_1BYTE_H

#include "tlv/formats/format.h"
#include "tlv/export.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file
 * @ingroup formats
 * @brief A fixed format: one tag byte, one length byte, and 0-255 value bytes.
 *
 * Every tag byte is valid; there are no reserved tags or length encodings.
 *
 * @note Writing any tag size other than one returns #TLV_ERR_INVALID_TAG_SIZE.
 */

/** @addtogroup formats
 * @{
 */

/** @brief Reader format for the fixed 1-byte encoding; a borrowed, immutable global. */
extern TLV_API const tlv_reader_format_t tlv_reader_format_fixed_1byte;
/** @brief Writer format for the fixed 1-byte encoding; a borrowed, immutable global. */
extern TLV_API const tlv_writer_format_t tlv_writer_format_fixed_1byte;

#ifdef __cplusplus
}
#endif
/** @} */

#endif
