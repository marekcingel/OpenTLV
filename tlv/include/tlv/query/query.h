#ifndef OPENTLV_QUERY_H
#define OPENTLV_QUERY_H

#include "tlv/error.h"
#include "tlv/reader/walker.h"
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
 * be constructed (see tlv_query_walk()).
 *
 * The query language is deliberately small: exact tag paths only. It carries
 * no wildcards, indexes, predicates or recursive search, and does not depend
 * on any format or profile, so the same text can address data in the reader
 * and, later, in other document models.
 */

/** @addtogroup traversal
 * @{
 */

/** @brief Maximum number of tags in a query: one per nesting level, `0..TLV_WALK_MAX_DEPTH`. */
enum { TLV_QUERY_MAX_STEPS = TLV_WALK_MAX_DEPTH + 1 };

/** @brief Maximum total number of tag bytes in a query, across all of its tags. */
enum { TLV_QUERY_MAX_BYTES = 512 };

/**
 * @brief A parsed query: the tags to follow from a top-level element down to the addressed ones.
 *
 * The structure is self-contained: it holds a copy of every tag's bytes, never
 * allocates and never points to other memory, so it can be copied freely. Build
 * it with tlv_query_parse() and read its tags with tlv_query_step(); a
 * zero-initialized query has no tags and is rejected by the functions that
 * take one. Each tag may have any length as long as all tags together stay
 * within #TLV_QUERY_MAX_BYTES.
 */
typedef struct tlv_query {
    /** Private: the bytes of all tags, one after another. */
    uint8_t bytes[TLV_QUERY_MAX_BYTES];
    /** Private: for each tag, the offset in `bytes` just past its last byte. */
    uint16_t ends[TLV_QUERY_MAX_STEPS];
    /** Number of tags, `1..TLV_QUERY_MAX_STEPS` for a parsed query. */
    size_t count;
} tlv_query_t;

/**
 * @brief Parses the text of a query.
 *
 * The text is one or more tags in hexadecimal, separated by a single `/`, for
 * example `6F/A5/50` or `9f02`. Each tag has an even, nonzero number of digits
 * in either case. Whitespace, empty steps
 * and a leading or trailing `/` are rejected. The tag bytes are not checked
 * against any format or profile.
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
 * @brief Returns one tag of a query.
 *
 * @param[in] query Parsed query.
 * @param[in] index Position of the tag, `0` for the top-level element.
 *
 * @return A tag that borrows the bytes stored in `query`, valid for as long as
 *         `query` is alive and unchanged. The empty tag if `query` is `NULL`
 *         or `index` is not below `query->count`.
 */
TLV_API tlv_tag_t tlv_query_step(const tlv_query_t* query, size_t index);

/**
 * @brief Incremental matcher that decides which elements of a preorder traversal a query addresses.
 *
 * This is the state behind tlv_query_walk(), exposed so that any preorder
 * traversal can run a query, such as the DER walker or a caller's own. Set it
 * up with tlv_query_matcher_init() and feed it every element, in order, with
 * tlv_query_matcher_visit(). The fields are private.
 */
typedef struct tlv_query_matcher {
    /** Query being matched; borrowed. */
    const tlv_query_t* query;
    /** Number of leading query tags matched by the ancestors of the next element. */
    size_t matched;
} tlv_query_matcher_t;

/**
 * @brief Prepares a matcher for one traversal.
 *
 * @param[out] matcher Matcher to initialize.
 * @param[in]  query   Parsed query; borrowed and must outlive the matcher.
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
 * cannot reach, with the same `depth` values tlv_walk_tree() passes to its
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

/**
 * @brief Calls a visitor for every element a query addresses.
 *
 * Traverses the input in preorder like tlv_walk_tree() and calls `visitor` for
 * each element addressed by `query`, in document order, with that element's
 * depth (always `query->count - 1`) and absolute offset. An element is
 * addressed when its tag equals the last query tag and its ancestors, from the
 * top level down, match the earlier ones.
 *
 * The whole input is traversed unless the visitor stops, so malformed data
 * after the last match is reported like any other error. Values are only
 * entered when `is_constructed` says so; with a `NULL` predicate only
 * one-tag queries can match.
 *
 * @param[in]  data          Input buffer.
 * @param[in]  size          Input size in bytes.
 * @param[in]  format        Reader format.
 * @param[in]  is_constructed Predicate receiving `format->context`, or `NULL` to
 *                           treat every value as opaque.
 * @param[in]  query         Parsed query.
 * @param[in]  max_depth     Maximum nesting depth, `0..TLV_WALK_MAX_DEPTH`.
 * @param[in]  max_elements  Bound on all traversed elements, matching or not.
 * @param[in]  visitor       Callback per addressed element. Required. Its view
 *                           borrows `data` and is valid only during the call.
 * @param[in]  context       Passed to the visitor unchanged; may be `NULL`.
 * @param[out] error_offset  Optional. On failure receives the failing element's
 *                           absolute offset; unchanged on success.
 *
 * @return #TLV_OK at the end of input, or when the visitor returns #TLV_VISIT_STOP.
 * @return #TLV_ERR_NULL_ARG if `query` or `visitor` is `NULL`, or as for tlv_walk_tree().
 * @return Any error of tlv_query_matcher_init() for an invalid `query`.
 * @return #TLV_ERR_VISITOR if the visitor returns #TLV_VISIT_ERROR or an unknown result.
 * @return Any other error of tlv_walk_tree(), propagated unchanged.
 *
 * @note Never allocates and does not recurse. No match is not an error: the
 *       visitor is simply never called.
 * @warning Visitor effects are not rolled back on error. The input and format
 *          must remain valid and unchanged during the call.
 * @see tlv_walk_tree
 */
TLV_API tlv_result_t tlv_query_walk(const uint8_t* data, size_t size,
                                    const tlv_reader_format_t* format,
                                    tlv_is_constructed_fn is_constructed, const tlv_query_t* query,
                                    size_t max_depth, size_t max_elements,
                                    tlv_tree_visitor_t visitor, void* context,
                                    size_t* error_offset);

#ifdef __cplusplus
}
#endif

/** @} */

#endif /* OPENTLV_QUERY_H */
