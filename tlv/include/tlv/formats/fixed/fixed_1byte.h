#ifndef OPENTLV_FORMATS_FIXED_1BYTE_H
#define OPENTLV_FORMATS_FIXED_1BYTE_H

#include "tlv/formats/format.h"

#ifdef __cplusplus
extern "C" {
#endif

/* One raw tag byte, one unsigned length byte, and 0 through 255 value bytes.
 * Every tag byte is valid; there are no reserved tags or length encodings.
 */
extern const tlv_reader_format_t tlv_reader_format_fixed_1byte;
extern const tlv_writer_format_t tlv_writer_format_fixed_1byte;

#ifdef __cplusplus
}
#endif
#endif
