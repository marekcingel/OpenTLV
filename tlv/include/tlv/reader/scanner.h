#ifndef OPENTLV_SCANNER_H
#define OPENTLV_SCANNER_H

#include "tlv/formats/format.h"
#include "tlv/schemas/schema.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Tries tlv_read() at each byte offset from start through size - 1, returning
 * the first complete candidate. out_offset is absolute relative to data;
 * consumed is its encoded size. out_entry borrows the input value.
 * A non-NULL schema requires a known tag and valid value length. An empty
 * schema rejects all candidates. No schema means syntactic validation only;
 * a match is not proof of an original element boundary.
 * Candidate parsing/validation errors are skipped, including truncated data.
 * No match (also start >= size) returns TLV_ERR_END_OF_BUFFER.
 * Requires format->read_tag/read_length and all output pointers. data may be
 * NULL only for size zero; schema->entries may be NULL only for count zero.
 * Invalid arguments return TLV_ERR_NULL_ARG. All outputs remain unchanged
 * on failure. Input, format and schema must stay valid during the call, and
 * the input must outlive the returned view. No allocation or value copying
 * occurs; custom callbacks must obey the allocation-free format contract.
 */
tlv_result_t tlv_scan(const uint8_t* data, size_t size, size_t start,
                      const tlv_reader_format_t* format, const tlv_schema_t* schema,
                      tlv_view_t* out_entry, size_t* out_offset, size_t* consumed);

#ifdef __cplusplus
}
#endif

#endif /* OPENTLV_SCANNER_H */
