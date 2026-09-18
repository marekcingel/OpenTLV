#ifndef OPENTLV_FORMATS_BER_H
#define OPENTLV_FORMATS_BER_H

#include "tlv/formats/format.h"
#include "tlv/writer/writer.h"
#include "tlv/length.h"
#include "tlv/export.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Identifier-octet class bits (ITU-T X.690 §8.1), independent of any
 * particular encoding-rule profile; shared by the DER and CER profiles. */
typedef enum tlv_asn1_class {
    TLV_ASN1_UNIVERSAL = 0,
    TLV_ASN1_APPLICATION = 1,
    TLV_ASN1_CONTEXT_SPECIFIC = 2,
    TLV_ASN1_PRIVATE = 3
} tlv_asn1_class_t;

/* Identifier octet bit layout below the class field (X.690 §8.1.2): bit 5 is
 * the constructed/primitive flag, and the low 5 bits are the low-tag-number
 * field, which escapes to high-tag-number form by being all-ones (31). */
enum {
    TLV_ASN1_CLASS_SHIFT = 6,
    TLV_ASN1_CONSTRUCTED_BIT = 0x20,
    TLV_ASN1_TAG_NUMBER_MASK = 0x1F,
    TLV_ASN1_LOW_TAG_LIMIT = 31
};

/* Raw BER-TLV tags up to TLV_TAG_CAPACITY, including high-tag-number form.
 * Definite lengths up to SIZE_MAX; writes use the shortest length encoding.
 * Reads accept nonminimal definite lengths and constructed indefinite lengths.
 * Tag bytes are preserved (including 9F 1C); ASN.1 semantics are not validated.
 */
extern TLV_API const tlv_reader_format_t tlv_reader_format_ber;
extern TLV_API const tlv_writer_format_t tlv_writer_format_ber;

/* Maximum simultaneous constructed scopes while resolving an indefinite
 * element, including that element and definite constructed descendants.
 * The implementation uses a fixed stack, without allocation or recursion.
 */
enum { TLV_BER_MAX_DEPTH = 64 };

/* Explicit indefinite encoding: tag + 80 + encoded children + 00 00.
 * The ordinary BER writer remains definite-length. Only constructed tags
 * are accepted. Size queries validate tag and overflow, without child bytes.
 * Writes also validate child framing and nesting before changing the buffer.
 * Children must not include the enclosing EOC or overlap the destination.
 * All outputs and writer position remain unchanged on failure.
 */
TLV_API tlv_result_t tlv_ber_indefinite_encoded_size(tlv_tag_t tag, size_t length, size_t* size);
TLV_API tlv_result_t tlv_ber_write_indefinite(uint8_t* data, size_t capacity, tlv_tag_t tag,
                                              const uint8_t* value, size_t length, size_t* written);
/* Requires a writer initialized with tlv_writer_format_ber. */
TLV_API tlv_result_t tlv_ber_writer_write_indefinite(tlv_writer_t* writer, tlv_tag_t tag,
                                                     const uint8_t* value, size_t length);

/* Nesting predicate for tree traversal; context is unused. */
TLV_API int tlv_ber_is_constructed(const void* context, const tlv_tag_t* tag);

/* Standalone BER definite-length field codec (X.690 §8.1.3), independent of
 * the format callbacks above and of any value payload. Uses tlv_length_t so
 * the decoded value has the same 64-bit range on every build, regardless of
 * the current build's size_t width; convert with tlv_length_to_size() before
 * using it as a native buffer length. Byte order is fixed by the BER
 * definite-length encoding itself; there is no runtime order parameter. */

/* Bytes needed for the shortest definite encoding of any tlv_length_t value:
 * one prefix octet plus up to 8 big-endian value octets for UINT64_MAX. Size
 * a destination buffer for tlv_ber_length_encode() with this constant. It is
 * smaller than the largest field tlv_ber_length_decode() can still accept,
 * since BER permits nonminimal (zero-padded) definite encodings with up to
 * 127 length octets (X.690 §8.1.3.4); decoding such padding does not require
 * a buffer this large, only reading one. */
enum { TLV_BER_LENGTH_MAX_ENCODED_SIZE = 9 };

/* Decode one definite-length field starting at data[0]: short form directly,
 * or long form as a length-of-length octet followed by that many big-endian
 * value octets. Nonminimal (zero-padded) long-form encodings are accepted
 * when the numeric value still fits tlv_length_t; excess leading octets must
 * be zero. The indefinite marker (0x80 alone) and the reserved 0xFF prefix
 * are rejected with TLV_ERR_INVALID_LENGTH, as is a padded value wider than
 * tlv_length_t or nonzero excess padding. Bounded by data_size: a field
 * claiming more length octets than are available returns
 * TLV_ERR_BUFFER_TOO_SHORT. data may be NULL only when data_size is zero;
 * value and consumed are required. NULL required pointers return
 * TLV_ERR_NULL_ARG. On any failure *value and *consumed are unchanged. This
 * does not process the indefinite-length marker or constructed EOC framing;
 * see tlv_ber_write_indefinite() and tlv_reader_format_ber for those. */
TLV_API tlv_result_t tlv_ber_length_decode(const uint8_t* data, size_t data_size,
                                           tlv_length_t* value, size_t* consumed);

/* Encode value using the shortest BER definite form (short form below 128,
 * otherwise long form with the minimal number of value octets). Supports a
 * size query: out may be NULL only when out_capacity is zero, in which case
 * no bytes are written and *written receives the required size. Otherwise
 * out_capacity smaller than the required size returns
 * TLV_ERR_BUFFER_TOO_SHORT with no partial write. written is required; NULL
 * required pointers return TLV_ERR_NULL_ARG. On any failure *written is
 * unchanged. */
TLV_API tlv_result_t tlv_ber_length_encode(tlv_length_t value, uint8_t* out, size_t out_capacity,
                                           size_t* written);

#ifdef __cplusplus
}
#endif
#endif
