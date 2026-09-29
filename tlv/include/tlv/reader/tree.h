#ifndef OPENTLV_TREE_READER_H
#define OPENTLV_TREE_READER_H

#include "tlv/reader/reader.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file
 * @ingroup traversal
 * @brief Iterative pull traversal over caller-owned input and structural storage.
 */

/** @addtogroup traversal
 * @{
 */

/** @brief Suggested nesting limit and frame capacity, not a library maximum. */
enum { TLV_TREE_DEFAULT_DEPTH = 64 };

/**
 * @brief Structural continuation for one entered constructed value.
 *
 * Contains only absolute offsets, never borrowed Elements or input pointers.
 * Storage belongs to the caller; do not modify active frames.
 */
typedef struct tlv_tree_frame {
    size_t end;    /**< Absolute end of the enclosing value. */
    size_t resume; /**< Absolute position after its complete encoded element. */
} tlv_tree_frame_t;

/**
 * @brief One complete borrowed element in the preorder tree stream.
 *
 * There are no ENTER/LEAVE events. Siblings have equal depth; a lower depth
 * returns to an enclosing sequence. Final end closes remaining scopes. Empty constructed
 * values still produce one item. Source ranges are relative to source.data.
 */
typedef struct tlv_tree_item {
    tlv_element_t element; /**< Complete semantic Element, borrowing input or Format storage. */
    tlv_source_t source;   /**< Borrowed encoded representation from the same decode. */
    size_t depth;          /**< Root elements have depth zero. */
    size_t offset;         /**< Absolute logical source offset of the element start. */
    int constructed;       /**< Nonzero when Format classifies the value as constructed. */
} tlv_tree_item_t;

/**
 * @brief Allocation-free, iterative preorder cursor composing the canonical Reader.
 *
 * Format alone decodes wire bytes. No recursion, schema validation, buffering,
 * I/O or recovery occurs. Frame capacity and max_depth are independent runtime
 * bounds; neither is limited by TLV_TREE_DEFAULT_DEPTH. A frame is required for
 * each entered nonempty constructed value, not for the root sequence.
 *
 * A constructed Element is published only when its complete encoded extent is
 * contiguous, as required by Reader. Thus incomplete descendants delay the
 * parent itself; this is not a partial-header or early-ENTER stream. Completed
 * subtrees can be discarded before later roots arrive. Every published Element,
 * Source and diagnostic retains the borrowed lifetime of its original storage.
 * The cursor stores no borrowed Element and does not need its previously
 * returned item to remain alive. Input replacement cannot relocate old views.
 *
 * Initialize through the functions below; do not modify members directly.
 */
typedef struct tlv_tree_reader {
    tlv_reader_t input;       /**< Canonical input window and traversal frontier. */
    tlv_tree_frame_t* frames; /**< Caller-owned structural storage, borrowed for traversal. */
    size_t capacity;          /**< Number of writable frames. */
    size_t max_depth;         /**< Largest permitted item depth; zero permits roots only. */
    size_t max_elements; /**< Maximum number of published items, including constructed items. */
    size_t count; /**< Number of items already published; skipped descendants do not count. */
    size_t depth; /**< Number of active enclosing frames. */
    tlv_tree_frame_t pending; /**< Continuation for the last item, before optional descent. */
    int descend_pending;      /**< Nonzero while the last item's nonempty subtree can be skipped. */
} tlv_tree_reader_t;

/**
 * @brief Initialize traversal of a complete, final input window.
 *
 * @param[out] reader Required cursor; unchanged on failure.
 * @param[in] data Borrowed contiguous input, NULL only if size is zero.
 * @param[in] size Available bytes.
 * @param[in] format Required readable Format, borrowed with its immutable context.
 * @param[in,out] frames Caller-owned frame storage; NULL only if capacity is zero.
 * @param[in] capacity Number of frames. Zero supports roots and subtree skipping.
 * @param[in] max_depth Largest allowed item depth; use TLV_TREE_DEFAULT_DEPTH as a default.
 * @param[in] max_elements Publication limit; zero permits only empty input.
 * @return #TLV_OK on success.
 * @return #TLV_ERR_NULL_ARG for missing required input, Format, cursor or storage.
 * @note Capacity may be smaller than max_depth; exhaustion is reported at descent.
 * @warning Frames must remain writable and alive while the cursor is used and
 *          must not overlap input or cursor storage. Input and Format lifetimes
 *          follow #tlv_reader_t and retained borrowed results.
 */
TLV_API tlv_result_t tlv_tree_reader_init(tlv_tree_reader_t* reader, const uint8_t* data,
                                          size_t size, const tlv_format_t* format,
                                          tlv_tree_frame_t* frames, size_t capacity,
                                          size_t max_depth, size_t max_elements);

/**
 * @brief Initialize non-final input, with the same storage contract as final initialization.
 *
 * @copydetails tlv_tree_reader_init
 * @note Unlike tlv_tree_reader_init(), empty or incomplete input returns
 *       #TLV_NEED_MORE_DATA until the caller supplies bytes or declares EOF.
 */
TLV_API tlv_result_t tlv_tree_reader_init_incremental(tlv_tree_reader_t* reader,
                                                      const uint8_t* data, size_t size,
                                                      const tlv_format_t* format,
                                                      tlv_tree_frame_t* frames, size_t capacity,
                                                      size_t max_depth, size_t max_elements);

/**
 * @brief Replace or extend the contiguous input window without copying.
 *
 * @param[in,out] reader Initialized cursor; required.
 * @param[in] data Replacement borrowed window, NULL only if size is zero.
 * @param[in] size Available bytes in the replacement window.
 * @param[in] discard Consumed prefix to discard, at most tlv_tree_reader_consumed().
 * @param[in] final_input Exactly 0 or 1; 1 declares EOF at the window end.
 * @return Same results as tlv_reader_set_input(); NULL reader returns #TLV_ERR_NULL_ARG.
 * @note Preserves absolute structural offsets. The replacement must retain all
 *       old bytes after discard unchanged, then optionally append bytes.
 *       On failure all state remains unchanged. Final input cannot be extended.
 * @warning Release borrowed results before moving or overwriting their storage.
 */
TLV_API tlv_result_t tlv_tree_reader_set_input(tlv_tree_reader_t* reader, const uint8_t* data,
                                               size_t size, size_t discard, int final_input);

/**
 * @brief Pull the next complete item in preorder.
 *
 * @param[in,out] reader Initialized cursor; required.
 * @param[out] item Required output; unchanged on non-success.
 * @return #TLV_OK when one item is published.
 * @return #TLV_NEED_MORE_DATA for exhausted or incomplete non-final root input.
 * @return #TLV_ERR_END_OF_BUFFER for exhausted final input.
 * @return #TLV_ERR_BUFFER_TOO_SHORT for incomplete final input or a child that
 *         exceeds its complete parent's value. Appending cannot repair the latter.
 * @return #TLV_ERR_LIMIT when depth, frame capacity or element count is exhausted.
 * @return #TLV_ERR_NULL_ARG for a NULL cursor or item.
 * @return Any other Reader error, propagated unchanged.
 * @note Non-success preserves traversal state and frame storage. Repeating a
 *       call with unchanged input is deterministic. Descent limits are checked
 *       after publishing the parent, so it can be skipped without entering it.
 * @warning The item borrows input and Format storage; it owns neither.
 */
TLV_API tlv_result_t tlv_tree_reader_next(tlv_tree_reader_t* reader, tlv_tree_item_t* item);

/**
 * @brief Pull an item with the original Reader failure detail, without a second decode.
 *
 * @param[in,out] reader Initialized cursor; required.
 * @param[out] item Required output; unchanged on non-success.
 * @param[out] diagnostic Optional detail with absolute logical offsets. Unchanged
 *            on success or tree argument/resource errors; filled on Reader outcomes.
 * @return Same results and state transitions as tlv_tree_reader_next().
 */
TLV_API tlv_result_t tlv_tree_reader_next_diag(tlv_tree_reader_t* reader, tlv_tree_item_t* item,
                                               tlv_reader_diagnostic_t* diagnostic);

/**
 * @brief Skip the last published item's descendants without decoding them.
 *
 * @param[in,out] reader Initialized cursor; required.
 * @return #TLV_OK when a pending nonempty constructed subtree was skipped.
 * @return #TLV_ERR_INVALID_ARG when there is no pending subtree.
 * @return #TLV_ERR_NULL_ARG for NULL reader.
 * @note May be called after a failed next() while descent is still pending.
 *       Skipped descendants do not count toward max_elements. No descendant
 *       validation occurs here; Format may already have scanned framing while
 *       decoding the parent. Closing enclosing scopes takes O(depth) work.
 */
TLV_API tlv_result_t tlv_tree_reader_skip_subtree(tlv_tree_reader_t* reader);

/**
 * @brief Get the prefix no longer needed for future traversal.
 * @param[in] reader Initialized cursor, or NULL.
 * @return Consumed prefix size in the current window, or zero for NULL.
 * @note A published parent does not consume its unvisited value. Retained
 *       borrowed results can require keeping bytes beyond this parser contract.
 */
TLV_API size_t tlv_tree_reader_consumed(const tlv_tree_reader_t* reader);

/**
 * @brief Get the absolute logical traversal frontier, including pending descent.
 * @param[in] reader Initialized cursor, or NULL.
 * @return Absolute next position, bounded by SIZE_MAX, or zero for NULL.
 */
TLV_API size_t tlv_tree_reader_offset(const tlv_tree_reader_t* reader);

/**
 * @brief Report complete exhaustion of final input and all nested scopes.
 * @param[in] reader Initialized cursor, or NULL.
 * @return 1 at final end, otherwise 0, including NULL and non-final empty input.
 */
TLV_API int tlv_tree_reader_at_end(const tlv_tree_reader_t* reader);

/** @} */
#ifdef __cplusplus
}
#endif
#endif /* OPENTLV_TREE_READER_H */
