#ifndef OPENTLV_FORMATS_BER_H
#define OPENTLV_FORMATS_BER_H

#include "tlv/formats/format.h"
#include "tlv/writer/writer.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Raw BER-TLV tags up to TLV_TAG_MAX_SIZE, including high-tag-number form.
 * Definite lengths up to SIZE_MAX; writes use the shortest length encoding.
 * Reads accept nonminimal definite lengths and constructed indefinite lengths.
 * Tag bytes are preserved (including 9F 1C); ASN.1 semantics are not validated.
 */
extern const tlv_reader_format_t tlv_reader_format_ber;
extern const tlv_writer_format_t tlv_writer_format_ber;

/* Maximum simultaneous constructed scopes while resolving an indefinite
 * element, including that element and definite constructed descendants.
 * The implementation uses a fixed stack, without allocation or recursion.
 */
#define TLV_BER_MAX_DEPTH 64

/* Explicit indefinite encoding: tag + 80 + encoded children + 00 00.
 * The ordinary BER writer remains definite-length. Only constructed tags
 * are accepted. Size queries validate tag and overflow, without child bytes.
 * Writes also validate child framing and nesting before changing the buffer.
 * Children must not include the enclosing EOC or overlap the destination.
 * All outputs and writer position remain unchanged on failure.
 */
tlv_result_t tlv_ber_indefinite_encoded_size(tlv_tag_t tag, size_t length, size_t* size);
tlv_result_t tlv_ber_write_indefinite(uint8_t* data, size_t capacity,
    tlv_tag_t tag, const uint8_t* value, size_t length, size_t* written);
/* Requires a writer initialized with tlv_writer_format_ber. */
tlv_result_t tlv_ber_writer_write_indefinite(tlv_writer_t* writer,
    tlv_tag_t tag, const uint8_t* value, size_t length);

/* Nesting predicate for tree traversal; context is unused. */
int tlv_ber_is_constructed(const void* context, const tlv_tag_t* tag);

#ifdef __cplusplus
}
#endif
#endif
