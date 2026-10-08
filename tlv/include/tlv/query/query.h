// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#ifndef OPENTLV_QUERY_H
#define OPENTLV_QUERY_H

#include "tlv/error.h"
#include "tlv/config.h"
#include "tlv/tree.h"
#if OPENTLV_READER
#include "tlv/reader/visitor.h"
#endif
#include "tlv/tag.h"
#include "tlv/export.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file
 * @ingroup traversal
 * @brief Path queries that address TLV elements by their nested tags.
 *
 * A query is a `/`-separated list of hexadecimal tags such as `6F/A5/50`. The
 * first tag names a top-level element, each following tag one of its direct
 * children, and the query addresses every element reached that way, in
 * document order. Tags are compared as raw bytes, so a query works for every
 * reader format; a path longer than one tag needs a format whose values can
 * be constructed (see tlv_query_visit_buffer()).
 *
 * This V1 query language is deliberately small: exact tag paths only. It carries
 * no wildcards, indexes, predicates or recursive search, and does not depend
 * on any format or standard, so the same text can address data in the reader
 * and, later, in other document models. The compiled extended language is
 * declared in @c tlv/query/program.h.
 */

/** @addtogroup traversal
 * @{
 */

/** @brief Capacity of the inline query path; independent of Tree Reader limits. */
enum { TLV_QUERY_MAX_STEPS = 65 };

/** @brief Maximum total number of tag bytes in a query, across all of its tags. */
enum { TLV_QUERY_MAX_BYTES = 512 };

/**
 * @brief A parsed query: the tags to follow from a top-level element down to the addressed ones.
 *
 * The opaque storage is self-contained: it holds a copy of every tag's bytes, never
 * allocates and never points to other memory, so it can be copied freely. Build
 * it with tlv_query_parse() and read its tags with tlv_query_step(); a
 * zero-initialized query has no tags and is rejected by the functions that
 * take one. Each tag may have any length as long as all tags together stay
 * within #TLV_QUERY_MAX_BYTES. sizeof(tlv_query_t) is 648 bytes; alignment is
 * that of uint64_t on the target. Do not inspect opaque members.
 */
typedef union tlv_query {
    uint8_t opaque[648]; /**< Fixed ABI capacity: 644 implementation bytes rounded to 8 bytes. */
    uint64_t alignment;  /**< Private alignment member; never read or write directly. */
} tlv_query_t;

/**
 * @brief Parses the text of a query.
 *
 * The text is one or more tags in hexadecimal, separated by a single `/`, for
 * example `6F/A5/50` or `9f02`. Each tag has an even, nonzero number of digits
 * in either case. Whitespace, empty steps
 * and a leading or trailing `/` are rejected. The tag bytes are not checked
 * against any format or standard.
 *
 * @param[in]  text         NUL-terminated query text.
 * @param[out] query        Receives the parsed query.
 * @param[out] error_offset Optional. On failure receives the index in `text` of
 *                          the offending character, or of the start of the
 *                          offending tag; unchanged on success.
 *
 * @return #TLV_OK on success.
 * @return #TLV_ERR_NULL_ARG if `text` or `query` is `NULL`.
 * @return #TLV_ERR_INVALID_ARG for a syntax error: an empty step, an odd number
 *         of digits, or a character other than a hexadecimal digit or `/`.
 * @return #TLV_ERR_LIMIT if the query has more than #TLV_QUERY_MAX_STEPS tags or
 *         more than #TLV_QUERY_MAX_BYTES tag bytes in total.
 *
 * @note Never allocates. On failure `*query` is unchanged.
 */
TLV_API tlv_result_t tlv_query_parse(const char* text, tlv_query_t* query, size_t* error_offset);

/**
 * @brief Parse a bounded V1 ASCII path without requiring a terminator.
 * @param[in] text Required readable span of exactly size bytes; not retained.
 * @param[in] size Text length in bytes, excluding any terminator.
 * @param[out] query Required self-contained output, unchanged on failure.
 * @param[out] error_offset Optional offending byte offset; unchanged on success.
 * @return #TLV_OK on success.
 * @return #TLV_ERR_NULL_ARG for a missing required pointer.
 * @return #TLV_ERR_INVALID_ARG for empty text, embedded NUL, non-ASCII or invalid V1 syntax.
 * @return #TLV_ERR_LIMIT above the inline step or tag-byte limits.
 * @note Never allocates or reads outside the supplied span. Output may overlap text.
 */
TLV_API tlv_result_t tlv_query_parse_n(const char* text, size_t size, tlv_query_t* query,
                                       size_t* error_offset);

/**
 * @brief Return the validated V1 step count.
 * @param[in] query Optional Query, borrowed for this call.
 * @return Step count, or zero for NULL, zero-initialized or corrupt storage.
 * @note Never allocates. O(step count) validation; storage remains unchanged.
 */
TLV_API size_t tlv_query_count(const tlv_query_t* query);

/**
 * @brief Format a V1 path as uppercase hexadecimal tags separated by slashes.
 * @param[in] query Required valid Query; borrowed for this call.
 * @param[out] output Writable output, or NULL with zero capacity for size discovery.
 * @param[in] capacity Available output bytes, including space for the terminator.
 * @param[out] required Required byte count including the trailing NUL; required.
 * @return #TLV_OK for discovery or a complete NUL-terminated write.
 * @return #TLV_ERR_NULL_ARG for a missing required pointer or NULL output with nonzero capacity.
 * @return #TLV_ERR_INVALID_ARG for invalid Query storage.
 * @return #TLV_ERR_BUFFER_TOO_SHORT if capacity is insufficient; required is set and output
 * unchanged.
 * @note Never allocates. Other failures preserve outputs. required must not overlap
 * Query or output storage; output may overlap Query, invalidating it after success.
 */
TLV_API tlv_result_t tlv_query_format(const tlv_query_t* query, char* output, size_t capacity,
                                      size_t* required);

/**
 * @brief Returns one tag of a query.
 *
 * @param[in] query Parsed query.
 * @param[in] index Position of the tag, `0` for the top-level element.
 *
 * @return A tag that borrows the bytes stored in `query`, valid for as long as
 *         `query` is alive and unchanged. The empty tag if `query` is `NULL`
 *         or `index` is out of range, or the stored boundaries are invalid.
 */
TLV_API tlv_tag_t tlv_query_step(const tlv_query_t* query, size_t index);

/**
 * @brief Incremental matcher that decides which elements of a preorder traversal a query addresses.
 *
 * This is the state behind tlv_query_visit_buffer(), exposed so that any preorder
 * traversal can run a query, such as the DER validation traversal or a caller's own. Set it
 * up with tlv_query_matcher_init() and feed it every element, in order, with
 * tlv_query_matcher_visit(). The fields are private.
 */
typedef union tlv_query_matcher {
    uint8_t opaque[16];    /**< Private continuation storage. */
    const void* alignment; /**< Private pointer alignment. */
    size_t size_alignment; /**< Private native-size alignment. */
} tlv_query_matcher_t;

/**
 * @brief Rebind suspended V1 matching to an equivalent Query copy.
 * @param[in,out] matcher Required initialized matcher; continuation is preserved.
 * @param[in] query Required equivalent Query; must outlive further matching.
 * @return #TLV_OK on success.
 * @return #TLV_ERR_NULL_ARG for a missing pointer.
 * @return #TLV_ERR_INVALID_STATE for an uninitialized matcher.
 * @return #TLV_ERR_INVALID_ARG for an invalid or different Query.
 * @note Never allocates. Failure preserves matcher. The old Query must remain
 * alive through this call. Use tlv_query_matcher_init() to reset a traversal.
 */
TLV_API tlv_result_t tlv_query_matcher_rebind(tlv_query_matcher_t* matcher,
                                              const tlv_query_t* query);

/**
 * @brief Prepares a matcher for one traversal.
 *
 * @param[out] matcher Matcher to initialize.
 * @param[in]  query   Parsed query; borrowed and must remain alive and unchanged
 *                    until the matcher is reset or successfully rebound.
 *
 * @return #TLV_OK on success.
 * @return #TLV_ERR_NULL_ARG if `matcher` or `query` is `NULL`.
 * @return #TLV_ERR_INVALID_ARG if `query` has no tags or more than #TLV_QUERY_MAX_STEPS.
 *
 * @note Never allocates. On failure `*matcher` is unchanged.
 */
TLV_API tlv_result_t tlv_query_matcher_init(tlv_query_matcher_t* matcher, const tlv_query_t* query);

/**
 * @brief Reports whether the next element of a preorder traversal is addressed by the query.
 *
 * Call it once for every element in preorder, including elements the query
 * cannot reach, with the same `depth` values tlv_tree_reader_visit() passes to its
 * visitor.
 *
 * @param[in,out] matcher Matcher set up by tlv_query_matcher_init().
 * @param[in]     tag     Tag of the element.
 * @param[in]     depth   Nesting depth of the element; zero for a top-level element.
 *
 * @return Nonzero if the element is addressed by the query, zero if it is not
 *         or if an argument is `NULL`.
 */
TLV_API int tlv_query_matcher_visit(tlv_query_matcher_t* matcher, const tlv_tag_t* tag,
                                    size_t depth);

#if OPENTLV_READER
/**
 * @brief Visit matching items from a caller-owned Tree Reader with resumable matching state.
 *
 * @param[in,out] reader Initialized cursor; required. Frames and runtime limits belong to caller.
 * @param[in,out] matcher Initialized matcher; required. Retain it across STOP and input
 * replacement.
 * @param[in] visitor Required callback for matches; follows tlv_tree_reader_visit().
 * @param[in] context Optional opaque callback context.
 * @param[out] error_offset Optional absolute failure offset; unchanged on success.
 * @return #TLV_ERR_NULL_ARG for missing reader, matcher, query or callback.
 * @return Any result of tlv_tree_reader_visit(), including #TLV_NEED_MORE_DATA.
 * @warning Keep the matcher's query alive and unchanged. Use a fresh matcher at
 *          the start of a tree; do not interleave unmatched pull operations.
 */
TLV_API tlv_result_t tlv_query_visit(tlv_tree_reader_t* reader, tlv_query_matcher_t* matcher,
                                     tlv_tree_visitor_t visitor, void* context,
                                     size_t* error_offset);

/**
 * @brief Calls a visitor for every element a query addresses.
 *
 * Traverses the input in preorder like tlv_tree_reader_visit() and calls `visitor` for
 * each element addressed by `query`, in document order, with that element's
 * depth (always `tlv_query_count(query) - 1`) and absolute offset. An element is
 * addressed when its tag equals the last query tag and its ancestors, from the
 * top level down, match the earlier ones.
 *
 * The whole input is traversed unless the visitor stops, so malformed data
 * after the last match is reported like any other error. Values are only
 * entered when `format->is_constructed` says so; with a `NULL`
 * `format->is_constructed` only one-tag queries can match.
 *
 * @param[in]  data          Input buffer.
 * @param[in]  size          Input size in bytes.
 * @param[in]  format        Reader format.
 * @param[in]  query         Parsed query.
 * @param[in]  max_depth     Runtime nesting limit; this convenience function owns
 * TLV_QUERY_MAX_STEPS frames.
 * @param[in]  max_elements  Bound on all traversed elements, matching or not.
 * @param[in]  visitor       Callback per addressed element. Required. Its element
 *                           borrows `data` and is valid only during the call.
 * @param[in]  context       Passed to the visitor unchanged; may be `NULL`.
 * @param[out] error_offset  Optional. On failure receives the failing element's
 *                           absolute offset; unchanged on success.
 *
 * @return #TLV_OK at the end of input, or when the visitor returns #TLV_VISIT_STOP.
 * @return #TLV_ERR_NULL_ARG if `query` or `visitor` is `NULL`, or as for tlv_tree_reader_visit().
 * @return Any error of tlv_query_matcher_init() for an invalid `query`.
 * @return #TLV_ERR_VISITOR if the visitor returns #TLV_VISIT_ERROR.
 * @return #TLV_ERR_CALLBACK if the visitor returns an unknown result.
 * @return Any other error of tlv_tree_reader_visit(), propagated unchanged.
 *
 * @note Never allocates and does not recurse. No match is not an error: the
 *       visitor is simply never called.
 * @warning Visitor effects are not rolled back on error. The input and format
 *          must remain valid and unchanged during the call.
 * @see tlv_query_visit
 */
TLV_API tlv_result_t tlv_query_visit_buffer(const uint8_t* data, size_t size,
                                            const tlv_format_t* format, const tlv_query_t* query,
                                            size_t max_depth, size_t max_elements,
                                            tlv_tree_visitor_t visitor, void* context,
                                            size_t* error_offset);

#endif

#ifdef __cplusplus
}
#endif

/** @} */

#endif /* OPENTLV_QUERY_H */
