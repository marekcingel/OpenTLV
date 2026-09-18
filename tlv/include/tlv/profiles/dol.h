#ifndef OPENTLV_PROFILES_DOL_H
#define OPENTLV_PROFILES_DOL_H

#include "tlv/tag.h"
#include "tlv/export.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Data Object Lists (EMV Contact Book 3 v4.4, October 2022, section 5.4):
 * PDOL, CDOL1/CDOL2 and DDOL all share one wire format, a flat sequence of
 * (tag, requested length) entries with no value bytes of their own -- each
 * entry requests how a later command's data should be formatted, not a
 * serialized value. This makes a DOL value a dedicated component rather
 * than ordinary TLV structure: reading it with tlv_read/tlv_walk would
 * misinterpret the one raw length byte as a BER length field and then look
 * for value bytes that were never encoded.
 *
 * Tags are ordinary BER tags (tlv/formats/asn1/ber.h), read generically up
 * to TLV_TAG_CAPACITY; every currently assigned EMV tag is one or two
 * bytes, but this component itself imposes no such restriction. Each
 * requested length is exactly one raw unsigned byte (0..255): there is no
 * BER long form and no value bytes follow it. No allocation and no
 * recursion are used.
 */

/* One DOL entry in wire order: a requested tag and the number of bytes a
 * command using this DOL should receive for it. Duplicate tags are legal
 * and are not deduplicated; each occurrence is reported as its own entry. */
typedef struct tlv_dol_entry {
    tlv_tag_t tag;
    size_t requested_length;
} tlv_dol_entry_t;

/* Called once per DOL entry, in wire order, by tlv_dol_read. entry is valid
 * only for the duration of the call. index is the entry's position, starting
 * at 0. Returning anything other than TLV_OK stops iteration and is returned
 * from tlv_dol_read unchanged; use TLV_ERR_VISITOR for the visitor's own
 * early stop, distinct from a parse failure. context is the borrowed
 * pointer passed to tlv_dol_read. */
typedef tlv_result_t (*tlv_dol_visit_fn)(const tlv_dol_entry_t* entry, size_t index, void* context);

/* Fixed ceiling on tlv_dol_limits_t.max_value_length: no currently defined
 * EMV data element eligible for a DOL entry exceeds it (Annex A's largest
 * bounded field is 252 bytes). Not configurable, matching
 * TLV_TAG_MAX_SUPPORTED_SIZE's convention for a hard architectural bound
 * rather than a runtime one. */
enum { TLV_DOL_MAX_VALUE_LENGTH = UINT8_MAX };

/* Bounds independent of size: the entry count tlv_dol_read/tlv_dol_write
 * visit, and the longest value tlv_dol_write's padding/truncation logic may
 * request from resolve for one entry. max_value_length must not exceed
 * TLV_DOL_MAX_VALUE_LENGTH. */
typedef struct tlv_dol_limits {
    size_t max_entries;
    size_t max_value_length;
} tlv_dol_limits_t;
extern TLV_API const tlv_dol_limits_t tlv_dol_default_limits;

/* Parses a raw DOL value, calling visit once per entry in wire order. Stops
 * at the first malformed entry, unmet limit, or visitor error; error_offset,
 * when set, then holds the failing entry's own starting offset (its tag, for
 * a tag or missing-length-byte failure). Reaching exactly size with no
 * partial entry is success, not an error; a dangling tag with no length byte
 * after it is TLV_ERR_BUFFER_TOO_SHORT. limits may be NULL to select
 * tlv_dol_default_limits. data may be NULL only when size is zero. */
TLV_API tlv_result_t tlv_dol_read(const uint8_t* data, size_t size, const tlv_dol_limits_t* limits,
                                  tlv_dol_visit_fn visit, void* context, size_t* error_offset);

/* EMV Book 3 5.4's two padding/truncation styles for fitting a resolved
 * value to its DOL-requested length. BINARY covers every data element
 * format other than plain right-justified numeric (alphabetic,
 * alphanumeric, alphanumeric special, binary, compressed numeric): pad on
 * the right with 0x00 when the available value is shorter than requested,
 * and drop trailing bytes when it is longer. NUMERIC covers right-justified
 * numeric data (BCD or binary amounts, counters and the like): pad on the
 * left with 0x00 when shorter, and drop leading bytes when longer. Which
 * style applies is a property of the requested tag's own data element
 * format, which only resolve (or the application behind it) knows. */
typedef enum tlv_dol_format { TLV_DOL_FORMAT_BINARY = 0, TLV_DOL_FORMAT_NUMERIC } tlv_dol_format_t;

/* Supplies the raw, unpadded bytes available for one DOL entry's tag, or
 * reports them unavailable, and applies EMV Book 3 5.4's rule for missing
 * data (tlv_dol_write fills entry->requested_length zero bytes).
 *
 * Called first with data == NULL, capacity == 0 and skip == 0, purely to
 * learn presence: *absent is 0 on entry, and the callback sets it nonzero to
 * report the value unavailable (in which case *available_length and
 * *format are not read). If present, the callback instead leaves *absent
 * zero and sets *available_length to the value's own complete length and
 * *format to the padding/truncation style tlv_dol_write should apply;
 * available_length may be less than, equal to, or greater than
 * entry->requested_length, but must not exceed
 * tlv_dol_limits_t.max_value_length, or tlv_dol_write fails with
 * TLV_ERR_LIMIT.
 *
 * If this first call reported presence and tlv_dol_write is producing
 * output (never for a size query, i.e. never when tlv_dol_write's own data
 * argument is NULL), the callback is called again with data != NULL to
 * produce bytes: it must write exactly capacity bytes, taken from the
 * value's own bytes starting at offset skip, into data. capacity is always
 * <= the *available_length reported by the first call, and skip is nonzero
 * only when *format was TLV_DOL_FORMAT_NUMERIC and available_length exceeded
 * entry->requested_length (dropping that many leading bytes). On this second
 * call *available_length, *format and *absent are not read by
 * tlv_dol_write and may be left unset. index is the entry's position in DOL
 * wire order, starting at 0, matching duplicate tags to their own
 * occurrence. context is the borrowed pointer passed to tlv_dol_write. */
typedef tlv_result_t (*tlv_dol_resolve_fn)(const tlv_dol_entry_t* entry, size_t index, size_t skip,
                                           uint8_t* data, size_t capacity, size_t* available_length,
                                           tlv_dol_format_t* format, int* absent, void* context);

/* Constructs the exact byte sequence dol (dol_size bytes) requests: for each
 * entry in wire order, resolve supplies the available value and its
 * padding/truncation style (see tlv_dol_resolve_fn and tlv_dol_format_t),
 * and the corresponding output segment is exactly entry->requested_length
 * bytes. *written is always exactly the sum of dol's own requested lengths,
 * independent of what resolve reports.
 *
 * data may be NULL with capacity 0 to query that size, as with
 * tlv_codec_encode; resolve is then not called at all, and may itself be
 * NULL. Otherwise resolve must not be NULL, and is called for every entry,
 * writing directly into data as each entry is processed: a later entry's
 * failure can leave data partially written, with unspecified contents
 * beyond that point, matching tlv_codec_t's convention. limits may be NULL
 * to select tlv_dol_default_limits. error_offset, when set on failure,
 * holds the failing entry's own starting offset within dol. */
TLV_API tlv_result_t tlv_dol_write(const uint8_t* dol, size_t dol_size, uint8_t* data,
                                   size_t capacity, const tlv_dol_limits_t* limits,
                                   tlv_dol_resolve_fn resolve, void* context, size_t* written,
                                   size_t* error_offset);

#ifdef __cplusplus
}
#endif
#endif /* OPENTLV_PROFILES_DOL_H */
