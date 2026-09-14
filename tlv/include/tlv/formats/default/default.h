#ifndef OPENTLV_FORMATS_DEFAULT_H
#define OPENTLV_FORMATS_DEFAULT_H

#include "tlv/formats/format.h"
#include "tlv/export.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Encoding: one raw tag byte and definite BER length up to 65535.
 * This is not a full BER-TLV tag implementation.
 * Writing any tag size other than one returns TLV_ERR_INVALID_TAG_SIZE.
 */
extern TLV_API const tlv_reader_format_t tlv_reader_format_default;
extern TLV_API const tlv_writer_format_t tlv_writer_format_default;

#ifdef __cplusplus
}
#endif
#endif
