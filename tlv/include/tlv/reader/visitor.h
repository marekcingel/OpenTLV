// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#ifndef OPENTLV_VISITOR_H
#define OPENTLV_VISITOR_H

#include "tlv/result.h"
#include "tlv/format.h"
#include "tlv/reader/tree.h"
#include "tlv/export.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file
 * @ingroup traversal
 * @brief Resumable visitor adapters over Reader and Tree Reader.
 */

/** @addtogroup traversal
 * @{
 */

/**
 * @brief Callback invoked by tlv_reader_visit() for each sequential element.
 *
 * @param element    Current element. The pointer is valid only during the
 *                callback; copied Elements borrow input or immutable Format storage.
 * @param context Caller context passed to tlv_reader_visit().
 *
 * @return A #tlv_visit_result_t. Unknown values produce #TLV_ERR_CALLBACK; #TLV_VISIT_ERROR
 * produces #TLV_ERR_VISITOR.
 */
typedef tlv_visit_result_t (*tlv_visitor_t)(const tlv_element_t* element, void* context);

/**
 * @brief Callback invoked by tlv_tree_reader_visit() for each element in preorder.
 *
 * @param element    Current element; its Tag and Value follow Reader borrowing and the
 *                pointer is valid only during the callback.
 * @param depth   Nesting depth; top-level elements have depth zero.
 * @param offset  Absolute offset of the encoded element start within the input.
 * @param context Caller context passed to tlv_tree_reader_visit().
 *
 * @return A #tlv_visit_result_t controlling traversal.
 */
typedef tlv_visit_result_t (*tlv_tree_visitor_t)(const tlv_element_t* element, size_t depth,
                                                 size_t offset, void* context);

/**
 * @brief Visit remaining sequential elements from an initialized Reader.
 *
 * Uses only canonical pull reads, without allocation, buffering or recursion.
 * Works with final and incremental input. The current element has already been
 * consumed when its callback runs, including on STOP or ERROR. Calling again
 * resumes at the next element; prior callbacks are never replayed or rolled back.
 *
 * @param[in,out] reader Initialized caller-owned cursor; required.
 * @param[in] visitor Required callback.
 * @param[in] context Opaque callback context; may be NULL.
 * @return #TLV_OK at final exhaustion or on #TLV_VISIT_STOP.
 * @return #TLV_NEED_MORE_DATA when more input is needed; supply it with
 *         tlv_reader_set_input() before resuming.
 * @return #TLV_ERR_NULL_ARG for a NULL cursor or callback.
 * @return #TLV_ERR_VISITOR on ERROR or an unknown callback result.
 * @return Any Reader error, propagated unchanged without retrying the decode.
 * @warning Do not mutate or advance this cursor, its input or Format inside
 *          the callback. The element pointer is valid only during the callback;
 *          a copied Element borrows the original input or Format storage under
 *          the same lifetime contract as direct pull results. Application
 *          recursion inside callbacks is outside the library traversal contract.
 */
TLV_API tlv_result_t tlv_reader_visit(tlv_reader_t* reader, tlv_visitor_t visitor, void* context);

/**
 * @brief Visit sequential elements with original Reader diagnostics.
 *
 * @copydetails tlv_reader_visit
 * @param[out] diagnostic Optional detail, cleared at entry. Filled on Reader
 *            failure or need-more-data with absolute offsets; remains clear on
 *            success and visitor errors. Borrowed diagnostic storage follows Reader.
 */
TLV_API tlv_result_t tlv_reader_visit_diag(tlv_reader_t* reader, tlv_visitor_t visitor,
                                           void* context, tlv_reader_diagnostic_t* diagnostic);

/**
 * @brief Visit remaining preorder items from an initialized Tree Reader.
 *
 * Uses only Tree Reader pull operations, without allocation or recursion.
 * Caller-owned frames and configured limits remain in force across calls.
 * STOP and ERROR leave the current item published: resuming after a constructed
 * parent visits its children unless the caller skips its subtree first.
 * Incremental input publishes complete elements only, including parents.
 *
 * @param[in,out] reader Initialized caller-owned cursor; required.
 * @param[in] visitor Callback, or NULL to validate only.
 * @param[in] context Opaque callback context; may be NULL.
 * @param[out] diagnostic Optional Reader detail, initialized at entry. INPUT coordinates
 *            are absolute in the stream, including discarded windows. Unknown locations
 *            remain unknown; visitor failures identify the visited item. Tag bytes and
 *            context strings remain borrowed from input/Format storage.
 * @return #TLV_OK at final exhaustion or on #TLV_VISIT_STOP.
 * @return #TLV_NEED_MORE_DATA when more input is needed; use
 *         tlv_tree_reader_set_input() before resuming.
 * @return #TLV_ERR_NULL_ARG for a NULL cursor.
 * @return #TLV_ERR_VISITOR on ERROR or an unknown callback result.
 * @return Any Tree Reader error, including resource limits, propagated unchanged.
 * @warning Callback effects are not rolled back. Cursor mutation and borrowed
 *          lifetimes follow tlv_reader_visit(); do not modify active frames.
 */
TLV_API tlv_result_t tlv_tree_reader_visit(tlv_tree_reader_t* reader, tlv_tree_visitor_t visitor,
                                           void* context, tlv_reader_diagnostic_t* diagnostic);

#ifdef __cplusplus
}
#endif

/** @} */

#endif /* OPENTLV_VISITOR_H */
