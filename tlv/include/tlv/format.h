#ifndef OPENTLV_FORMAT_H
#define OPENTLV_FORMAT_H

#include "tlv/types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Stateless operations with optional borrowed, immutable configuration.
 * The descriptor and context must outlive readers/writers using them.
 * Callbacks must not allocate, retain buffers, or access beyond size/capacity.
 * On success, read callbacks report consumed bytes (at least one for tags)
 * and initialize their output. Tags must fit TLV_TAG_MAX_SIZE.
 * write_tag(context, NULL, 0, tag, &size) validates the tag and reports its encoded size;
 * this query must not write. Actual writes report the same size as the query.
 * length_size validates the length and reports the exact write_length size.
 * All sizes are in bytes. Callback errors propagate unchanged.
 */
typedef struct tlv_format {
    const void* context;
    tlv_result_t (*read_tag)(const void* context, const uint8_t* data,
                             size_t size, tlv_tag_t* tag, size_t* consumed);
    tlv_result_t (*write_tag)(const void* context, uint8_t* data,
                              size_t capacity, const tlv_tag_t* tag, size_t* written);
    tlv_result_t (*read_length)(const void* context, const uint8_t* data,
                                size_t size, size_t* length, size_t* consumed);
    tlv_result_t (*write_length)(const void* context, uint8_t* data,
                                 size_t capacity, size_t length, size_t* written);
    tlv_result_t (*length_size)(const void* context, size_t length, size_t* size);
} tlv_format_t;

/* Encoding: one raw tag byte and definite BER length up to 65535.
 * This is not a full BER-TLV tag implementation.
 */
extern const tlv_format_t tlv_format_default;

/* One raw tag byte, one unsigned length byte, and 0 through 255 value bytes.
 * Every tag byte is valid; there are no reserved tags or length encodings.
 */
extern const tlv_format_t tlv_format_fixed_1byte;

/* Raw BER-TLV tags up to TLV_TAG_MAX_SIZE, including high-tag-number form.
 * Definite lengths up to SIZE_MAX; writes use the shortest length encoding.
 * Reads accept nonminimal definite lengths. Indefinite lengths are rejected.
 * Tag bytes are preserved (including 9F 1C); ASN.1 semantics are not validated.
 */
extern const tlv_format_t tlv_format_ber;

/* Canonical ASN.1 DER identifiers and definite lengths. Validates universal
 * primitive/constructed bits, but does not inspect values or nested headers.
 * Use tlv/der.h for bounded recursive validation and error offsets.
 */
extern const tlv_format_t tlv_format_der;

#ifdef __cplusplus
}
#endif

#endif /* OPENTLV_FORMAT_H */
