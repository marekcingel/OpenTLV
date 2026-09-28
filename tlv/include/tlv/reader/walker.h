#ifndef OPENTLV_WALKER_H
#define OPENTLV_WALKER_H

#include "tlv/error.h"
#include "tlv/format.h"
#include "tlv/reader/reader.h"
#include "tlv/export.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file
 * @ingroup traversal
 * @brief Visitor-based traversal of sequential and nested TLV elements.
 */

/** @addtogroup traversal
 * @{
 */

/**
 * @brief Value a visitor callback returns to control traversal.
 */
typedef enum tlv_visit_result {
    /** Continue with the next element. */
    TLV_VISIT_CONTINUE = 0,
    /** Stop traversal immediately; the walk still returns #TLV_OK. */
    TLV_VISIT_STOP = 1,
    /** Abort traversal; the walk returns #TLV_ERR_VISITOR. */
    TLV_VISIT_ERROR = 2
} tlv_visit_result_t;

/**
 * @brief Callback invoked by tlv_walk() for each sequential element.
 *
 * @param element    Current element. The pointer is valid only during the
 *                callback; its value borrows the input data.
 * @param context Caller context passed to tlv_walk().
 *
 * @return A #tlv_visit_result_t. Any unknown value is treated as an error.
 */
typedef tlv_visit_result_t (*tlv_visitor_t)(const tlv_element_t* element, void* context);

/**
 * @brief Visits each sequential element using the generic reader.
 *
 * Does not allocate or recurse into values. Returns #TLV_OK at the end of
 * input (including empty input) or on #TLV_VISIT_STOP. No further elements
 * are read after a stop or error.
 *
 * @param[in] data    Input buffer. May be `NULL` only when `size` is zero.
 * @param[in] size    Input size in bytes.
 * @param[in] format  Reader format; `decode` are required,
 *                    even for empty input.
 * @param[in] visitor Callback invoked per element. Required.
 * @param[in] context Passed to the visitor unchanged; may be `NULL`.
 *
 * @return #TLV_OK at the end of input or on #TLV_VISIT_STOP.
 * @return #TLV_ERR_NULL_ARG for invalid arguments.
 * @return #TLV_ERR_VISITOR if the visitor returns #TLV_VISIT_ERROR or an
 *         unknown result.
 * @return Any reader error, propagated unchanged.
 *
 * @warning The input and format must remain valid and unchanged during
 *          traversal. Effects of earlier callbacks are not rolled back on error.
 */
TLV_API tlv_result_t tlv_walk(const uint8_t* data, size_t size, const tlv_format_t* format,
                              tlv_visitor_t visitor, void* context);

/**
 * @brief Maximum `max_depth` accepted by tlv_walk_tree().
 */
enum { TLV_WALK_MAX_DEPTH = 64 };

/**
 * @brief Callback invoked by tlv_walk_tree() for each element in preorder.
 *
 * @param element    Current element; its value borrows the input data and the
 *                pointer is valid only during the callback.
 * @param depth   Nesting depth; top-level elements have depth zero.
 * @param offset  Absolute offset of the element's tag within the input.
 * @param context Caller context passed to tlv_walk_tree().
 *
 * @return A #tlv_visit_result_t controlling traversal.
 */
typedef tlv_visit_result_t (*tlv_tree_visitor_t)(const tlv_element_t* element, size_t depth,
                                                 size_t offset, void* context);

/**
 * @brief Traverses nested elements in preorder.
 *
 * Constructed values (identified by `format->is_constructed`) are traversed
 * as bounded views of the input. There is no allocation and no C recursion.
 * A `NULL` visitor validates only. #TLV_VISIT_STOP succeeds immediately.
 *
 * @param[in]  data          Input buffer.
 * @param[in]  size          Input size in bytes.
 * @param[in]  format        Reader format. A `NULL` `format->is_constructed`
 *                           treats every value as opaque.
 * @param[in]  max_depth     Maximum nesting depth, `0..TLV_WALK_MAX_DEPTH`.
 * @param[in]  max_elements  Bound on all visited nodes; zero permits only empty input.
 * @param[in]  visitor       Callback per element; may be `NULL` to validate only.
 * @param[in]  context       Passed to the visitor unchanged.
 * @param[out] error_offset  Optional. On failure receives the failing element's
 *                           absolute offset; unchanged on success.
 *
 * @return #TLV_OK on success or when the visitor returns #TLV_VISIT_STOP.
 * @return #TLV_ERR_LIMIT if `max_depth` exceeds #TLV_WALK_MAX_DEPTH, or the
 *         depth or element limit is exceeded.
 * @return #TLV_ERR_VISITOR if the visitor requests an error stop.
 * @return Any reader error, propagated unchanged.
 *
 * @warning Callback effects are not rolled back. The input, format and
 *          borrowed views follow the lifetimes documented for tlv_walk().
 * @see tlv_walk
 */
TLV_API tlv_result_t tlv_walk_tree(const uint8_t* data, size_t size, const tlv_format_t* format,
                                   size_t max_depth, size_t max_elements,
                                   tlv_tree_visitor_t visitor, void* context, size_t* error_offset);

/**
 * @brief Traverse while retaining the original reader failure detail without reparsing.
 *
 * @copydetails tlv_walk_tree
 *
 * @param[out] diagnostic Optional reader failure detail, with absolute offsets.
 * Cleared at entry; remains clear for walker/resource/visitor errors and success.
 */
TLV_API tlv_result_t tlv_walk_tree_diag(const uint8_t* data, size_t size,
                                        const tlv_format_t* format, size_t max_depth,
                                        size_t max_elements, tlv_tree_visitor_t visitor,
                                        void* context, size_t* error_offset,
                                        tlv_reader_diagnostic_t* diagnostic);

#ifdef __cplusplus
}
#endif

/** @} */

#endif /* OPENTLV_WALKER_H */
