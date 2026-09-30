#ifndef OPENTLV_BER_INTERNAL_H
#define OPENTLV_BER_INTERNAL_H
#include "tlv/layout.h"
#include "tlv/builtins/asn1/ber.h"
/* Private ASN.1 field adapter over generic Variable primitives. Retains BER's
 * leading-digit and reserved-length policy; DER/CER add their own restrictions.
 * This is not the reusable, protocol-independent wire implementation. */
extern const tlv_field_layout_t tlv_ber_wire;
extern const tlv_field_layout_t tlv_der_fields;
extern const tlv_field_layout_t tlv_cer_fields;

/* Shared shortest definite-length encoder and sizing callbacks. */
tlv_result_t tlv_ber_write_length(const void*, uint8_t*, size_t, tlv_size_t, size_t*);
tlv_result_t tlv_ber_length_size(const void*, tlv_size_t, size_t*);

/* BER high-tag-number form: the tag number is carried across one or more
 * base-128 digit octets following the identifier octet (X.690 §8.1.2.4.2). */
enum {
    TLV_BER_TAG_DIGIT_MASK = 0x7F,             /* payload bits of one digit octet */
    TLV_BER_TAG_DIGIT_CONTINUATION_BIT = 0x80, /* set on every digit octet but the last */
    TLV_BER_TAG_DIGIT_BITS = 7                 /* tag-number bits carried per digit octet */
};

/* BER length octet layout (X.690 §8.1.3). TLV_BER_LENGTH_LONG_FORM_BIT and
 * TLV_BER_TAG_DIGIT_CONTINUATION_BIT share the value 0x80 but name distinct
 * roles: one flags a multi-octet length, the other a multi-octet tag digit. */
enum {
    TLV_BER_LENGTH_LONG_FORM_BIT = 0x80, /* long form (indefinite length when alone) */
    TLV_BER_LENGTH_COUNT_MASK = 0x7F,    /* long form: count of following length octets */
    TLV_BER_LENGTH_RESERVED_OCTET = 0xFF /* reserved; never a valid length prefix */
};

/* BER indefinite-length framing (X.690 §8.1.3.6): one 0x80 length octet,
 * eventually followed by a two-octet 00 00 end-of-contents marker. */
enum { TLV_BER_INDEFINITE_LENGTH_OCTET_SIZE = 1, TLV_BER_EOC_SIZE = 2 };

/* Available bytes of the original BER length field, including malformed or
 * truncated fields. Discards the decoded quantity and never reads beyond size. */
size_t tlv_ber_length_field_size(const uint8_t* data, size_t size);

/* Traverse only framing, skipping primitive contents in one step, starting just
 * after a tag whose length field begins at data[0]. indefinite selects
 * whether the outer scope itself is EOC-terminated (the caller already
 * consumed its introducing 0x80). Each nested frame's end is a hard bound
 * inherited from the closest definite enclosing scope; an EOC outside that
 * bound cannot terminate a nested value. On success, *value_size receives
 * the content length up to (but excluding) any matching outer EOC and
 * *consumed receives the same plus that EOC's 2 bytes when indefinite.
 * Bounded by TLV_BER_MAX_DEPTH nested scopes; no allocation, no recursion.
 * Shared by tlv_format_ber, tlv_ber_write_indefinite, and CER. */
tlv_result_t tlv_ber_scan_contents(const uint8_t* data, size_t size, int indefinite,
                                   size_t* value_size, size_t* consumed);
tlv_result_t tlv_ber_scan_contents_diag(const uint8_t*, size_t, int, size_t*, size_t*,
                                        tlv_format_error_t*);
tlv_result_t tlv_asn1_indefinite_measure(const void*, const tlv_element_t*, tlv_encoding_t*,
                                         tlv_format_error_t*);
tlv_result_t tlv_asn1_indefinite_encode(const void*, const tlv_element_t*, uint8_t*, size_t,
                                        size_t*, tlv_format_error_t*);
#endif
