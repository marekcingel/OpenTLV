#ifndef OPENTLV_BUILTINS_EMV_DOL_H
#define OPENTLV_BUILTINS_EMV_DOL_H

#include "tlv/error.h"
#include "tlv/tag.h"
#include "tlv/export.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file
 * @ingroup profiles
 * @brief Data Object List (DOL) parsing and construction (EMV Contact Book 3 v4.4, section 5.4).
 *
 * PDOL, CDOL1/CDOL2 and DDOL all share one wire format: a flat sequence of
 * (tag, requested length) entries with no value bytes of their own. Each
 * entry requests how a later command's data should be formatted, not a
 * serialized value. This makes a DOL value a dedicated component rather than
 * ordinary TLV structure.
 *
 * @warning Do not read a DOL with tlv_read() or tlv_walk(): they would
 *          misinterpret the one raw length byte as a BER length field and
 *          then look for value bytes that were never encoded.
 *
 * Tags are ordinary BER tags (tlv/builtins/asn1/ber.h), read generically up to
 * #TLV_ASN1_TAG_MAX_SIZE bytes; every currently assigned EMV tag is one or two bytes,
 * but this component itself imposes no such restriction. Each requested
 * length is exactly one raw unsigned byte (0..255): there is no BER long
 * form and no value bytes follow it. No allocation and no recursion are used.
 */

/** @addtogroup profiles
 * @{
 */

/**
 * @brief One DOL entry in wire order.
 *
 * Duplicate tags are legal and are not deduplicated; each occurrence is
 * reported as its own entry.
 */
typedef struct tlv_dol_entry {
    /** Requested tag; borrows the DOL bytes given to the reader, valid only for the callback. */
    tlv_tag_t tag;
    /** Number of bytes a command using this DOL should receive for the tag. */
    size_t requested_length;
} tlv_dol_entry_t;

/**
 * @brief Callback invoked once per DOL entry, in wire order, by tlv_dol_read().
 *
 * Returning anything other than #TLV_OK stops iteration and is returned from
 * tlv_dol_read() unchanged. Use #TLV_ERR_VISITOR for the visitor's own early
 * stop, distinct from a parse failure.
 *
 * @param entry   The entry; valid only for the duration of the call.
 * @param index   The entry's position, starting at 0.
 * @param context Borrowed pointer passed to tlv_dol_read().
 *
 * @return #TLV_OK to continue, or an error code to stop.
 */
typedef tlv_result_t (*tlv_dol_visit_fn)(const tlv_dol_entry_t* entry, size_t index, void* context);

/**
 * @brief Fixed ceiling on #tlv_dol_limits_t::max_value_length.
 *
 * No currently defined EMV data element eligible for a DOL entry exceeds it
 * (Annex A's largest bounded field is 252 bytes). Not configurable, matching
 * the other fixed limits of the library, a hard bound rather than a runtime one.
 */
enum { TLV_DOL_MAX_VALUE_LENGTH = UINT8_MAX };

/**
 * @brief Bounds on DOL reading and writing, independent of the input size.
 */
typedef struct tlv_dol_limits {
    /** Maximum entry count that tlv_dol_read() and tlv_dol_write() visit. */
    size_t max_entries;
    /**
     * Longest value tlv_dol_write()'s padding and truncation logic may
     * request from `resolve` for one entry. Must not exceed
     * #TLV_DOL_MAX_VALUE_LENGTH.
     */
    size_t max_value_length;
} tlv_dol_limits_t;

/** @brief Default limits used when a function receives `NULL` limits. */
extern TLV_API const tlv_dol_limits_t tlv_dol_default_limits;

/**
 * @brief Parses a raw DOL value, calling a visitor once per entry in wire order.
 *
 * Stops at the first malformed entry, unmet limit, or visitor error.
 * Reaching exactly `size` with no partial entry is success, not an error.
 *
 * @param[in]  data         Raw DOL value. May be `NULL` only when `size` is zero.
 * @param[in]  size         Size of `data` in bytes.
 * @param[in]  limits       Limits, or `NULL` for #tlv_dol_default_limits.
 * @param[in]  visit        Callback per entry.
 * @param[in]  context      Passed to `visit` unchanged.
 * @param[out] error_offset Optional. On failure receives the failing entry's own
 *                          starting offset (its tag, for a tag or
 *                          missing-length-byte failure).
 *
 * @return #TLV_OK if all entries were visited.
 * @return #TLV_ERR_BUFFER_TOO_SHORT for a dangling tag with no length byte.
 * @return #TLV_ERR_LIMIT if a limit is exceeded.
 * @return Any error returned by `visit`, unchanged.
 */
TLV_API tlv_result_t tlv_dol_read(const uint8_t* data, size_t size, const tlv_dol_limits_t* limits,
                                  tlv_dol_visit_fn visit, void* context, size_t* error_offset);

/**
 * @brief EMV Book 3 section 5.4's two padding/truncation styles for fitting a resolved value.
 *
 * Which style applies is a property of the requested tag's own data element
 * format, which only `resolve` (or the application behind it) knows.
 */
typedef enum tlv_dol_format {
    /**
     * Every data element format other than plain right-justified numeric
     * (alphabetic, alphanumeric, alphanumeric special, binary, compressed
     * numeric). Pads on the right with 0x00 when the available value is
     * shorter than requested, and drops trailing bytes when it is longer.
     */
    TLV_DOL_FORMAT_BINARY = 0,
    /**
     * Right-justified numeric data (BCD or binary amounts, counters and the
     * like). Pads on the left with 0x00 when shorter, and drops leading bytes
     * when longer.
     */
    TLV_DOL_FORMAT_NUMERIC
} tlv_dol_format_t;

/**
 * @brief Callback supplying the raw, unpadded bytes available for one DOL entry's tag.
 *
 * Applies EMV Book 3 section 5.4's rule for missing data: when the value is
 * unavailable, tlv_dol_write() fills `entry->requested_length` zero bytes.
 *
 * The callback is called first with `data == NULL`, `capacity == 0` and
 * `skip == 0`, purely to learn presence. `*absent` is 0 on entry, and the
 * callback sets it nonzero to report the value unavailable (in which case
 * `*available_length` and `*format` are not read). If present, the callback
 * leaves `*absent` zero, sets `*available_length` to the value's own
 * complete length, and sets `*format` to the padding/truncation style
 * tlv_dol_write() should apply. `*available_length` may be less than, equal
 * to, or greater than `entry->requested_length`, but must not exceed
 * #tlv_dol_limits_t::max_value_length, or tlv_dol_write() fails with
 * #TLV_ERR_LIMIT.
 *
 * If that first call reported presence and tlv_dol_write() is producing
 * output (never for a size query, that is, never when tlv_dol_write()'s own
 * `data` argument is `NULL`), the callback is called again with
 * `data != NULL` to produce bytes. It must write exactly `capacity` bytes,
 * taken from the value's own bytes starting at offset `skip`, into `data`.
 * `capacity` is always at most the `*available_length` reported by the first
 * call, and `skip` is nonzero only when `*format` was
 * #TLV_DOL_FORMAT_NUMERIC and `available_length` exceeded
 * `entry->requested_length` (dropping that many leading bytes). On this
 * second call `*available_length`, `*format` and `*absent` are not read by
 * tlv_dol_write() and may be left unset.
 *
 * @param[in]  entry            The entry being resolved.
 * @param[in]  index            The entry's position in DOL wire order, starting at
 *                              0, matching duplicate tags to their own occurrence.
 * @param[in]  skip             Offset into the value at which to start copying.
 * @param[out] data             Destination, or `NULL` for the presence query.
 * @param[in]  capacity         Number of bytes to write to `data`.
 * @param[out] available_length Receives the value's complete length.
 * @param[out] format           Receives the padding/truncation style.
 * @param[out] absent           Set nonzero to report the value unavailable.
 * @param[in]  context          Borrowed pointer passed to tlv_dol_write().
 *
 * @return #TLV_OK on success, or an error code that propagates from
 *         tlv_dol_write() unchanged.
 */
typedef tlv_result_t (*tlv_dol_resolve_fn)(const tlv_dol_entry_t* entry, size_t index, size_t skip,
                                           uint8_t* data, size_t capacity, size_t* available_length,
                                           tlv_dol_format_t* format, int* absent, void* context);

/**
 * @brief Constructs the exact byte sequence a DOL requests.
 *
 * For each entry in wire order, `resolve` supplies the available value and
 * its padding/truncation style (see #tlv_dol_resolve_fn and
 * #tlv_dol_format_t), and the corresponding output segment is exactly
 * `entry->requested_length` bytes. `*written` is always exactly the sum of
 * the DOL's own requested lengths, independent of what `resolve` reports.
 *
 * `data` may be `NULL` with `capacity` 0 to query that size, as with
 * tlv_codec_encode(); `resolve` is then not called at all, and may itself
 * be `NULL`. Otherwise `resolve` must not be `NULL` and is called for every
 * entry, writing directly into `data` as each entry is processed.
 *
 * @param[in]  dol          The DOL value, `dol_size` bytes.
 * @param[in]  dol_size     Size of `dol` in bytes.
 * @param[out] data         Destination; `NULL` with zero `capacity` queries the size.
 * @param[in]  capacity     Destination capacity in bytes.
 * @param[in]  limits       Limits, or `NULL` for #tlv_dol_default_limits.
 * @param[in]  resolve      Callback supplying each entry's value; may be `NULL`
 *                          only for a size query.
 * @param[in]  context      Passed to `resolve` unchanged.
 * @param[out] written      Receives the total size.
 * @param[out] error_offset Optional. On failure receives the failing entry's own
 *                          starting offset within `dol`.
 *
 * @return #TLV_OK on success.
 * @return #TLV_ERR_BUFFER_TOO_SHORT if `capacity` is insufficient.
 * @return #TLV_ERR_LIMIT if a limit is exceeded.
 * @return Any parse error of tlv_dol_read(), or any `resolve` error, unchanged.
 *
 * @warning A later entry's failure can leave `data` partially written, with
 *          unspecified contents beyond that point, matching #tlv_codec_t's
 *          convention.
 */
TLV_API tlv_result_t tlv_dol_write(const uint8_t* dol, size_t dol_size, uint8_t* data,
                                   size_t capacity, const tlv_dol_limits_t* limits,
                                   tlv_dol_resolve_fn resolve, void* context, size_t* written,
                                   size_t* error_offset);

#ifdef __cplusplus
}
#endif
/** @} */

#endif /* OPENTLV_BUILTINS_EMV_DOL_H */
