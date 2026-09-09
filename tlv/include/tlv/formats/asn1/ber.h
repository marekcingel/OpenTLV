#ifndef OPENTLV_FORMATS_BER_H
#define OPENTLV_FORMATS_BER_H

#include "tlv/formats/format.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Raw BER-TLV tags up to TLV_TAG_MAX_SIZE, including high-tag-number form.
 * Definite lengths up to SIZE_MAX; writes use the shortest length encoding.
 * Reads accept nonminimal definite lengths. Indefinite lengths are rejected.
 * Tag bytes are preserved (including 9F 1C); ASN.1 semantics are not validated.
 */
extern const tlv_reader_format_t tlv_reader_format_ber;
extern const tlv_writer_format_t tlv_writer_format_ber;

/* Nesting predicate for tree traversal; context is unused. */
int tlv_ber_is_constructed(const void* context, const tlv_tag_t* tag);

#ifdef __cplusplus
}
#endif
#endif
