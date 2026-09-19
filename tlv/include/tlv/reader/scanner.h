#ifndef OPENTLV_SCANNER_H
#define OPENTLV_SCANNER_H

#include "tlv/formats/format.h"
#include "tlv/schemas/schema.h"
#include "tlv/export.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file
 * @ingroup traversal
 * @brief Recovery scan for a plausible TLV element at any byte offset.
 */

/** @addtogroup traversal
 * @{
 */

/**
 * @brief Finds the first complete candidate element at or after an offset.
 *
 * Tries tlv_read() at each byte offset from `start` through `size - 1` and
 * returns the first complete candidate. Candidate parsing and validation
 * errors, including truncated data, are skipped.
 *
 * A non-`NULL` `schema` requires a known tag and a valid value length; an
 * empty schema rejects all candidates. With no schema only syntactic
 * validation applies.
 *
 * @param[in]  data       Input buffer. May be `NULL` only when `size` is zero.
 * @param[in]  size       Input size in bytes.
 * @param[in]  start      First offset to try, relative to `data`.
 * @param[in]  format     Reader format; `read_tag` and `read_length` are required.
 * @param[in]  schema     Optional schema restricting candidates; may be `NULL`.
 *                        `schema->entries` may be `NULL` only for a zero count.
 * @param[out] out_entry  Receives the matched element; borrows the input value.
 * @param[out] out_offset Receives the match offset, absolute relative to `data`.
 * @param[out] consumed   Receives the encoded size of the match.
 *
 * @return #TLV_OK if a candidate matched.
 * @return #TLV_ERR_END_OF_BUFFER if there is no match, including `start >= size`.
 * @return #TLV_ERR_NULL_ARG for invalid arguments.
 *
 * @note All outputs remain unchanged on failure.
 * @note No allocation or value copying occurs; custom callbacks must obey
 *       the allocation-free format contract.
 * @warning A match is not proof of an original element boundary. The input,
 *          format and schema must stay valid during the call, and the input
 *          must outlive the returned view.
 */
TLV_API tlv_result_t tlv_scan(const uint8_t* data, size_t size, size_t start,
                              const tlv_reader_format_t* format, const tlv_schema_t* schema,
                              tlv_view_t* out_entry, size_t* out_offset, size_t* consumed);

#ifdef __cplusplus
}
#endif

/** @} */

#endif /* OPENTLV_SCANNER_H */
