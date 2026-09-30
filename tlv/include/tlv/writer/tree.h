#ifndef OPENTLV_TREE_WRITER_H
#define OPENTLV_TREE_WRITER_H

#include "tlv/writer/writer.h"
#include "tlv/defaults.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file
 * @ingroup writer
 * @brief Allocation-free iterative construction using caller-owned bounded storage.
 */
/** @addtogroup writer
 * @{
 */

/** @brief One open constructed element; caller-owned, immutable while active. */
typedef struct tlv_tree_writer_frame {
    tlv_tag_t tag; /**< Borrowed identifier, retained from begin until successful end. */
    size_t start;  /**< Start of the accumulated Value in the destination buffer. */
} tlv_tree_writer_frame_t;

/**
 * @brief Bounded tree writer composing Format measure/encode without recursion or allocation.
 *
 * Children are accumulated in output storage. end() copies their complete bytes
 * to scratch and encodes the parent back into output using the canonical Writer.
 * Scratch must fit the largest Value closed by end(), not the entire encoding.
 * Each ancestor can copy its descendants again: worst-case work is O(bytes * depth).
 * No maximum header width, in-place encoding or header patching is assumed.
 * Content-dependent measurement and trailers are supported.
 *
 * Only the prefix returned by tlv_tree_writer_size() is final. Open subtrees
 * move when ancestors close. Diagnostics use absolute offsets in the current
 * destination buffer, not predicted final offsets of unfinished descendants.
 * This is bounded output, including for indefinite Formats; the complete-element
 * Format contract does not expose a streaming header/trailer capability.
 *
 * Initialize through init(); do not modify members or active storage directly.
 */
typedef struct tlv_tree_writer {
    tlv_writer_t output;             /**< Canonical output cursor, including provisional bytes. */
    tlv_tree_writer_frame_t* frames; /**< Borrowed caller-owned stack. */
    size_t capacity;                 /**< Stack capacity in frames. */
    size_t depth;                    /**< Number of open constructed elements. */
    size_t max_depth;                /**< Maximum item depth; roots have depth zero. */
    size_t max_elements;     /**< Maximum begin/write operations; complete subtrees count once. */
    size_t count;            /**< Successful begin/write operations. */
    uint8_t* scratch;        /**< Borrowed workspace, overwritten by end(). */
    size_t scratch_capacity; /**< Workspace capacity in bytes. */
} tlv_tree_writer_t;

/**
 * @brief Initialize an empty bounded output sequence without allocating.
 * @param[out] writer Required cursor; unchanged on failure.
 * @param[in,out] data Output storage; NULL only for zero size.
 * @param[in] size Output capacity in bytes.
 * @param[in] format Borrowed writable immutable Format and context; required.
 * @param[in,out] frames Caller-owned stack; NULL only for zero capacity.
 * @param[in] capacity Stack capacity; each begin needs one frame, even when empty.
 * @param[in,out] scratch Workspace; NULL only for zero scratch_capacity.
 * @param[in] scratch_capacity Workspace capacity in bytes; zero permits empty parents.
 * @param[in] max_depth Largest item depth; zero allows roots only. Use
 *                     TLV_TREE_DEFAULT_DEPTH for the suggested runtime limit.
 * @param[in] max_elements Maximum successful begin/write calls; SIZE_MAX is effectively unbounded.
 * @return #TLV_OK on success; #TLV_ERR_NULL_ARG for missing storage or write capability.
 * @warning Cursor, frames, scratch and output storage must be disjoint and live
 *          throughout use. Format/context must remain alive and immutable.
 */
TLV_API tlv_result_t tlv_tree_writer_init(tlv_tree_writer_t* writer, uint8_t* data, size_t size,
                                          const tlv_format_t* format,
                                          tlv_tree_writer_frame_t* frames, size_t capacity,
                                          uint8_t* scratch, size_t scratch_capacity,
                                          size_t max_depth, size_t max_elements);

/**
 * @brief Open a constructed element without emitting its header yet.
 * @param[in,out] writer Initialized cursor; required.
 * @param[in] tag Identifier, borrowed until successful end() or cursor abandonment.
 * @return #TLV_OK on success; #TLV_ERR_NULL_ARG for NULL writer or invalid Tag pointer.
 * @return #TLV_ERR_INVALID_TAG if Format does not classify tag as constructed.
 * @return #TLV_ERR_LIMIT if frame capacity, item depth or element count is exhausted.
 * @note Failure leaves state and output unchanged. Wire representability is
 *       checked at end(), once the Value is known. Empty parents require end().
 * @warning Tag bytes must remain immutable and must not overlap output, scratch,
 *          cursor or frame storage. Unlike single-element writing, begin retains Tag.
 */
TLV_API tlv_result_t tlv_tree_writer_begin(tlv_tree_writer_t* writer, tlv_tag_t tag);

/**
 * @brief Open a parent with structured failure detail.
 * @param[in,out] writer Initialized cursor; required.
 * @param[in] tag Borrowed identifier as for tlv_tree_writer_begin().
 * @param[out] diagnostic Optional failure detail; unchanged on success.
 * @return Same results and guarantees as tlv_tree_writer_begin().
 */
TLV_API tlv_result_t tlv_tree_writer_begin_diag(tlv_tree_writer_t* writer, tlv_tag_t tag,
                                                tlv_writer_diagnostic_t* diagnostic);

/**
 * @brief Append a primitive or already-complete constructed Element.
 * @param[in,out] writer Initialized cursor; required.
 * @param[in] element Readable semantic input; required, not retained, disjoint from output storage.
 * @return #TLV_ERR_LIMIT on item depth/count exhaustion, otherwise the result of
 *         tlv_writer_write_element(), including #TLV_ERR_NULL_ARG for NULL writer.
 * @note Does not traverse or validate complete subtree contents. Advances and
 *       counts only on success. Previously accumulated bytes remain valid on failure.
 * @warning Callback errors may modify unused bytes at or beyond the unchanged cursor.
 */
TLV_API tlv_result_t tlv_tree_writer_write_element(tlv_tree_writer_t* writer,
                                                   const tlv_element_t* element);

/**
 * @brief Append a complete Element with structured failure detail.
 * @param[in,out] writer Initialized cursor; required.
 * @param[in] element Input as for tlv_tree_writer_write_element().
 * @param[out] diagnostic Optional detail; unchanged on success. Offsets are absolute
 *                        in the current output buffer, including provisional storage.
 * @return Same results and guarantees as tlv_tree_writer_write_element().
 */
TLV_API tlv_result_t tlv_tree_writer_write_element_diag(tlv_tree_writer_t* writer,
                                                        const tlv_element_t* element,
                                                        tlv_writer_diagnostic_t* diagnostic);

/**
 * @brief Close the innermost parent using its complete accumulated Value.
 * @param[in,out] writer Initialized cursor; required.
 * @return #TLV_OK on success; #TLV_ERR_NULL_ARG for NULL writer.
 * @return #TLV_ERR_INVALID_ARG when no parent is open.
 * @return #TLV_ERR_BUFFER_TOO_SHORT for insufficient scratch or output storage.
 * @return Any Format measurement/encoding error, propagated unchanged.
 * @note On failure, cursor, active frames and all previously accumulated output
 *       bytes are preserved, including after callback failure. The parent stays open.
 *       Scratch and unused destination bytes may change. No implicit end or allocation.
 */
TLV_API tlv_result_t tlv_tree_writer_end(tlv_tree_writer_t* writer);

/**
 * @brief Close the innermost parent with structured failure detail.
 * @param[in,out] writer Initialized cursor; required.
 * @param[out] diagnostic Optional detail; unchanged on success. Scratch shortage uses
 *                        TLV_WRITER_OP_END with scratch available/required byte counts.
 * @return Same results and guarantees as tlv_tree_writer_end().
 */
TLV_API tlv_result_t tlv_tree_writer_end_diag(tlv_tree_writer_t* writer,
                                              tlv_writer_diagnostic_t* diagnostic);

/**
 * @brief Verify that every begin has a matching end, without changing state.
 * @param[in] writer Initialized cursor; required.
 * @return #TLV_OK if complete, #TLV_ERR_INVALID_ARG for an open parent,
 *         or #TLV_ERR_NULL_ARG for NULL writer. Does not seal the cursor.
 */
TLV_API tlv_result_t tlv_tree_writer_finish(const tlv_tree_writer_t* writer);

/**
 * @brief Return the final output prefix containing only closed root elements.
 * @param[in] writer Initialized cursor, or NULL.
 * @return Stable prefix size in bytes, or zero for NULL. Provisional bytes are excluded.
 */
TLV_API size_t tlv_tree_writer_size(const tlv_tree_writer_t* writer);

/** @} */
#ifdef __cplusplus
}
#endif
#endif
