#ifndef OPENTLV_TREE_WRITER_H
#define OPENTLV_TREE_WRITER_H

#include "tlv/writer/writer.h"
#include "tlv/defaults.h"
#include "tlv/tree.h"

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
    uint8_t* tags;           /**< Optional caller-owned storage for open identifiers. */
    size_t tags_capacity;    /**< Capacity of tags; storage never grows implicitly. */
    size_t tags_used;        /**< Bytes held by currently open identifiers. */
} tlv_tree_writer_t;

/**
 * @brief Configure bounded copying of open Tags instead of retaining input views.
 * @param[in,out] writer Initialized cursor without open parents; required.
 * @param[in,out] data Caller-owned storage, disjoint from all other storage and inputs.
 * NULL with zero capacity restores borrowed-Tag mode. Storage must outlive use.
 * @param[in] capacity Available bytes; an explicit empty Tag consumes one byte.
 * @return TLV_OK, TLV_ERR_NULL_ARG, or TLV_ERR_INVALID_ARG when parents are open.
 * @note begin() copies Tags in this mode; end() releases capacity on success.
 * Failure preserves the configuration. Exhaustion at begin returns TLV_ERR_LIMIT.
 */
TLV_API tlv_result_t tlv_tree_writer_set_tag_storage(tlv_tree_writer_t* writer, uint8_t* data,
                                                     size_t capacity);

/**
 * @brief Consume one canonical structural event without reconstructing depth transitions.
 * @param[in,out] writer Initialized cursor; required.
 * @param[in] event Required event. BEGIN opens its Tag (ignoring source Value),
 * ELEMENT writes a primitive, END closes the innermost parent. Depth must match.
 * @return Underlying begin/write/end result; TLV_ERR_INVALID_ARG for malformed
 * ordering, unknown kinds or skipped END; TLV_ERR_INVALID_TAG for incompatible
 * destination classification. Errors preserve cursor and accumulated output.
 * @warning In borrowed mode BEGIN retains Tag until END. Configure tag storage
 * to release input after every successful event. On failure retain the current
 * event for retry; do not advance the producer. Source metadata is ignored.
 */
TLV_API tlv_result_t tlv_tree_writer_write_event(tlv_tree_writer_t* writer,
                                                 const tlv_tree_event_t* event);

/**
 * @brief Consume an event with Writer diagnostics.
 * @param[in,out] writer Initialized cursor; required.
 * @param[in] event Required canonical event.
 * @param[out] diagnostic Optional failure detail; unchanged on success.
 * @return Same results and guarantees as tlv_tree_writer_write_event().
 */
TLV_API tlv_result_t tlv_tree_writer_write_event_diag(tlv_tree_writer_t* writer,
                                                      const tlv_tree_event_t* event,
                                                      tlv_writer_diagnostic_t* diagnostic);

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
 * @param[in] tag Identifier, borrowed until successful end() or cursor abandonment,
 * or copied when tlv_tree_writer_set_tag_storage() has configured storage.
 * @return #TLV_OK on success; #TLV_ERR_NULL_ARG for NULL writer or invalid Tag pointer.
 * @return #TLV_ERR_INVALID_TAG if Format does not classify tag as constructed.
 * @return #TLV_ERR_LIMIT if frame capacity, item depth or element count is exhausted.
 * @note Failure leaves state and output unchanged. Wire representability is
 *       checked at end(), once the Value is known. Empty parents require end().
 * @warning Tag bytes must remain immutable and must not overlap output, scratch,
 *          cursor, frame or Tag storage. Without configured Tag storage, begin retains Tag.
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

/**
 * @brief Supply the next semantic node in preorder, without encoding it.
 * @param[in,out] context Caller-owned traversal state.
 * @param[out] element Borrowed Tag and primitive Value; constructed Value is ignored.
 * @param[out] depth Root-relative depth, starting at zero.
 * @param[out] constructed Nonzero for a parent, including an empty parent.
 * @return #TLV_OK for an item, #TLV_ERR_END_OF_BUFFER at final end, or a source error.
 * @warning Tags must remain immutable and alive until traversal completes; primitive
 *          Values must remain readable until the next callback. Storage must not
 *          overlap the measurement workspace. Depth may increase only after a parent.
 */
typedef tlv_result_t (*tlv_tree_writer_next_fn)(void* context, tlv_element_t* element,
                                                size_t* depth, int* constructed);

/** @brief Caller-owned bounded storage for exact tree measurement and staging. */
typedef struct tlv_tree_writer_workspace {
    tlv_tree_writer_frame_t* frames; /**< Structural stack, disjoint from byte storage. */
    size_t frame_capacity;           /**< Number of available frames. */
    uint8_t* data;                   /**< Staged encoding, valid on successful measurement. */
    size_t data_capacity;            /**< Available staged output bytes. */
    uint8_t* scratch;                /**< Shared workspace for closing all parents. */
    size_t scratch_capacity;         /**< Available scratch bytes. */
    size_t required_data;            /**< Next required output capacity on storage exhaustion. */
    size_t required_scratch;         /**< Next required scratch capacity on storage exhaustion. */
} tlv_tree_writer_workspace_t;

/**
 * @brief Pull one structural event for bounded tree measurement.
 * @param[in,out] context Producer state.
 * @param[out] event One event on TLV_OK; unchanged otherwise.
 * @return TLV_OK, TLV_ERR_END_OF_BUFFER at final EOF, or a producer error.
 * @warning BEGIN Tags must outlive measurement; other payloads need only survive
 * until the next callback. No callbacks may mutate the measurement workspace.
 */
typedef tlv_result_t (*tlv_tree_event_next_fn)(void* context, tlv_tree_event_t* event);

/**
 * @brief Measure and stage a canonical balanced event stream through Tree Writer.
 * @param[in] format Borrowed destination Format; required.
 * @param[in] next Required event producer; consumed even on failure.
 * @param[in,out] context Producer state passed unchanged to next.
 * @param[in,out] workspace Caller-owned bounded staging storage; required.
 * @param[in] max_depth Maximum node depth, roots zero.
 * @param[in] max_elements Maximum BEGIN/ELEMENT count; END does not count.
 * @param[out] size Exact encoded size on success; unchanged otherwise.
 * @param[out] diagnostic Optional Writer failure detail.
 * @return Source/Writer result, including INVALID_ARG for missing END or skipped content.
 * @note Uses the storage, required-capacity and replay contracts of
 * tlv_tree_writer_measure(). NEED_MORE_DATA aborts this one-shot helper; use a
 * persistent Tree Writer and write_event() for resumable transformations.
 */
TLV_API tlv_result_t tlv_tree_writer_measure_events(const tlv_format_t* format,
                                                    tlv_tree_event_next_fn next, void* context,
                                                    tlv_tree_writer_workspace_t* workspace,
                                                    size_t max_depth, size_t max_elements,
                                                    size_t* size,
                                                    tlv_writer_diagnostic_t* diagnostic);

/**
 * @brief Measure a preorder tree through canonical Tree Writer encoding, without allocating.
 *
 * Content-dependent Formats need actual encoded children. Consequently this operation
 * stages the complete encoding in workspace.data, calling both measure and encode.
 * The successful prefix can be reused through tlv_writer_copy_encoded() without replay.
 * All parents are opened and closed iteratively by Tree Writer, including empty ones.
 *
 * @param[in] format Borrowed immutable writable Format and context; required.
 * @param[in] next Required preorder source callback; consumed, including on failure.
 * @param[in,out] context Opaque source state, passed unchanged to next.
 * @param[in,out] workspace Required disjoint caller-owned storage; never allocated here.
 * @param[in] max_depth Maximum item depth; roots have depth zero.
 * @param[in] max_elements Maximum number of source items.
 * @param[out] size Exact encoded size on success; unchanged on failure.
 * @param[out] diagnostic Optional Writer failure detail; unchanged on success.
 * @return #TLV_OK on success; source and Writer errors propagated unchanged.
 * @return #TLV_ERR_INVALID_ARG for invalid preorder depth; #TLV_ERR_INVALID_TAG
 *         for a constructed classification incompatible with the destination Format.
 * @return #TLV_ERR_LIMIT for insufficient frames or exceeded traversal limits.
 * @return #TLV_ERR_BUFFER_TOO_SHORT on workspace exhaustion. Only this storage
 *         check sets required_data/required_scratch above capacity; callback errors,
 *         even with the same code, leave both zero. Requirements reset on each call.
 * @note After increasing storage, restart with a fresh source. Requirements are a
 *       lower bound discovered during traversal, not a prediction of final size.
 * @warning Failure may modify workspace bytes. Format and source callbacks must be
 *          deterministic for replay. No recursion, allocation, or Format-specific path.
 */
TLV_API tlv_result_t tlv_tree_writer_measure(const tlv_format_t* format,
                                             tlv_tree_writer_next_fn next, void* context,
                                             tlv_tree_writer_workspace_t* workspace,
                                             size_t max_depth, size_t max_elements, size_t* size,
                                             tlv_writer_diagnostic_t* diagnostic);

/** @} */
#ifdef __cplusplus
}
#endif
#endif
