#ifndef OPENTLV_FUZZ_FORMATS_H
#define OPENTLV_FUZZ_FORMATS_H

#include "common.h"
#if OPENTLV_FORMAT_DEFAULT
#include "tlv/formats/default/default.h"
#endif
#if OPENTLV_FORMAT_FIXED_1BYTE
#include "tlv/formats/fixed/fixed_1byte.h"
#endif
#if OPENTLV_FORMAT_BER
#include "tlv/formats/asn1/ber.h"
#endif
#if OPENTLV_FORMAT_DER
#include "tlv/formats/asn1/der.h"
#endif

/* Raw-byte formats have no built-in nesting rule. This test convention lets
 * the walker exercise their nested values too: bit 0x20 denotes a container. */
static inline int fuzz_constructed(const void* context, const tlv_tag_t* tag) {
    (void)context;
    return (tag->data[0] & 0x20) != 0;
}

static const struct {
    const tlv_reader_format_t* reader;
    const tlv_writer_format_t* writer;
    tlv_is_constructed_fn constructed;
} fuzz_formats[] = {
#if OPENTLV_FORMAT_DEFAULT
    {&tlv_reader_format_default, &tlv_writer_format_default, fuzz_constructed},
#endif
#if OPENTLV_FORMAT_FIXED_1BYTE
    {&tlv_reader_format_fixed_1byte, &tlv_writer_format_fixed_1byte, fuzz_constructed},
#endif
#if OPENTLV_FORMAT_BER
    {&tlv_reader_format_ber, &tlv_writer_format_ber, tlv_ber_is_constructed},
#endif
#if OPENTLV_FORMAT_DER
    {&tlv_reader_format_der, &tlv_writer_format_der, tlv_der_is_constructed},
#endif
    {NULL, NULL, NULL}
};

#endif
