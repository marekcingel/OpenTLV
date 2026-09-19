#ifndef OPENTLV_FORMATS_DEFAULT_H
#define OPENTLV_FORMATS_DEFAULT_H

#include "tlv/formats/format.h"
#include "tlv/export.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file default.h
 * @brief The default format: a one-byte tag with a definite BER length.
 *
 * Encoding: one raw tag byte and a definite BER length up to 65535. This is
 * not a full BER-TLV tag implementation; use tlv/formats/asn1/ber.h for that.
 *
 * @note Writing any tag size other than one returns #TLV_ERR_INVALID_TAG_SIZE.
 */

/** @brief Reader format for the default encoding; a borrowed, immutable global. */
extern TLV_API const tlv_reader_format_t tlv_reader_format_default;
/** @brief Writer format for the default encoding; a borrowed, immutable global. */
extern TLV_API const tlv_writer_format_t tlv_writer_format_default;

#ifdef __cplusplus
}
#endif
#endif
