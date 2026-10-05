// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#ifndef OPENTLV_DOCUMENT_H
#define OPENTLV_DOCUMENT_H

#include "tlv/export.h"
#include "tlv/error.h"
#include "tlv/format.h"
#include "tlv/query/query.h"
#include "tlv/query/program.h"
#include "tlv/writer/tree.h"
#include "tlv/reader/visitor.h"
#include "tlv/tag.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file
 * @ingroup document
 * @brief Optional mutable TLV document that owns its data and can be modified and encoded again.
 *
 * The reader, writer and traversal APIs are zero-copy and never allocate.
 * This component is a separate convenience layer for applications that must
 * change an existing message: tlv_document_parse() copies the input into an
 * owned tree of nodes, the tree can then be searched, changed, extended and
 * shortened, and tlv_document_encode() writes it out again through the
 * writer of the chosen format.
 *
 * The document is built only on the public reader, writer and query APIs and
 * works with any format: the reader and writer formats and the nesting
 * predicate are supplied through the Format in #tlv_document_options_t, as for
 * tlv_tree_reader_init(). Nothing in the allocation-free core depends on it. It is
 * an optional component (`OPENTLV_DOCUMENT`, see tlv/config.h) and the only
 * OpenTLV component that allocates memory.
 *
 * **Ownership.** A #tlv_document_t owns every node, tag and value in it.
 * Nodes are handed out as #tlv_node_t pointers that borrow from the document:
 * a node pointer, and the tag and value pointers read from it, stay valid until
 * the node is erased, its value is replaced, or the document is freed. Erasing
 * a node invalidates that node and all of its descendants. Nothing refers
 * to the buffer passed to tlv_document_parse() once it returns.
 *
 * **Encoding.** The tree stores decoded elements, not the original bytes, so
 * tlv_document_encode() produces the encoding of the writer format. Input that
 * the writer would spell differently, such as a non-minimal length or an
 * indefinite-length BER element, is normalised. Input that already uses the
 * writer's spelling, which is what the OpenTLV formats write, encodes back to
 * identical bytes.
 *
 * **Threads.** A document is not synchronised; concurrent reads are safe,
 * any modification needs exclusive access.
 */

/** @addtogroup document
 * @{
 */

/** @brief Default for #tlv_document_options_t::max_elements: bounds memory taken for one document.
 */
enum { TLV_DOCUMENT_DEFAULT_MAX_ELEMENTS = 65536 };

/**
 * @brief Caller-supplied memory functions used by a document.
 *
 * Both callbacks are required when an allocator is given. The allocator is
 * copied into the document; `context` must stay valid until the document is
 * freed.
 */
typedef struct tlv_allocator {
    /** Opaque pointer passed to both callbacks. */
    void* context;
    /** Returns at least `size` bytes, aligned for any object, or `NULL` when memory is exhausted.
     * `size` is never zero. */
    void* (*allocate)(void* context, size_t size);
    /** Releases memory returned by `allocate`. Never called with `NULL`. */
    void (*release)(void* context, void* memory);
} tlv_allocator_t;

/**
 * @brief Format descriptor and limits of a document.
 *
 * Initialize with tlv_document_options_init(). The document copies this
 * structure, but the format, the format's context and the allocator context are
 * borrowed and must outlive the document.
 * @see @docs{guides/memory,format context ownership and lifetime}
 */
typedef struct tlv_document_options {
    /**
     * Format used to parse input and values and to encode the document.
     * Required; must be able to both read and write, see tlv_format_can_read()
     * and tlv_format_can_write(). `format->is_constructed` tells which tags
     * hold nested elements, or `NULL` to keep every value opaque; its answer
     * is taken when a node is created and stays with the node.
     */
    const tlv_format_t* format;
    /**
     * Runtime maximum nesting depth (default TLV_TREE_DEFAULT_DEPTH); top-level elements have depth
     * zero and an element that would lie deeper is rejected with #TLV_ERR_LIMIT.
     */
    size_t max_depth;
    /** Maximum number of elements in the document, including nested ones. */
    size_t max_elements;
    /** Allocator, or `NULL` to use the C library's `malloc()` and `free()`. */
    const tlv_allocator_t* allocator;
} tlv_document_options_t;

/** @brief An owned mutable TLV document. Opaque; create with tlv_document_create() or
 * tlv_document_parse(). */
typedef struct tlv_document tlv_document_t;

/** @brief One element of a document. Opaque; owned by its document. */
typedef struct tlv_node tlv_node_t;

/**
 * @brief Resumable owning consumer of a Tree Reader, optionally limited to one subtree.
 *
 * Opaque and allocating. A builder keeps its unfinished document private. Free
 * it with tlv_document_builder_free(), including after successful completion.
 */
typedef struct tlv_document_builder tlv_document_builder_t;

/**
 * @brief Create a builder for a complete tree stream or the last published subtree.
 *
 * With NULL `root`, consume a fresh reader through final end, including all roots.
 * Otherwise `root` must be the last item published by `reader`, with no intervening
 * pulls or subtree skips. Its node becomes the document's only root at depth zero.
 * The root's tag and primitive value are copied immediately; descendants are
 * copied by tlv_document_builder_consume(). No borrowed item is retained.
 *
 * @param[in] options Document options; copied. The format must be the reader's exact
 *                    descriptor. Depth limits are relative to the materialized root;
 *                    element limits count only materialized nodes. Reader limits still apply.
 * @param[in,out] reader Initialized cursor; borrowed until completion or destruction.
 * @param[in] root Optional last published item, still valid during this call.
 * @param[out] builder Required output; NULL on failure.
 * @return #TLV_OK on success.
 * @return #TLV_ERR_NULL_ARG for missing required arguments.
 * @return #TLV_ERR_INVALID_ARG for a format mismatch, a non-fresh whole-stream cursor,
 *         or an invalid root extent.
 * @return #TLV_ERR_LIMIT if the root exceeds document limits.
 * @return #TLV_ERR_OUT_OF_MEMORY if allocation fails.
 * @return Any other error of tlv_document_create().
 * @note Does not advance the reader. Failure releases all allocations.
 * @warning Do not pull or skip on the reader while the builder is active. Input
 *          replacement through tlv_tree_reader_set_input() is allowed. The format
 *          and allocator contexts must outlive both builder and resulting document.
 *          Reader's complete contiguous constructed-element contract still applies.
 */
TLV_API tlv_result_t tlv_document_builder_create(const tlv_document_options_t* options,
                                                 tlv_tree_reader_t* reader,
                                                 const tlv_tree_item_t* root,
                                                 tlv_document_builder_t** builder);

/**
 * @brief Consume structural events and transfer ownership only on completion.
 *
 * A whole-stream builder completes at final end. A subtree builder completes
 * after its root and descendants, without decoding the following sibling; the
 * cursor is ready to continue outside that subtree. Empty and primitive roots
 * complete without another pull. Enclosing END events outside the selected
 * subtree remain pending, so the frontier may precede an enclosing trailer.
 * This validates only the selected range.
 *
 * @param[in,out] builder Active builder; required.
 * @param[out] document Required output; receives the owned document on success,
 *                      otherwise NULL. Release with tlv_document_free().
 * @param[out] error_offset Optional absolute source offset on traversal or node
 *                         creation failure, including NEED_MORE_DATA; unchanged on success.
 * @param[out] diagnostic Optional borrowed Reader failure detail, with the same
 *                       lifetime and update rules as tlv_tree_reader_next_diag().
 * @return #TLV_OK when the completed document is transferred to the caller.
 * @return #TLV_NEED_MORE_DATA when more input is needed; builder state is retained.
 * @return #TLV_ERR_NULL_ARG for missing required arguments.
 * @return #TLV_ERR_INVALID_ARG if already completed or failed.
 * @return #TLV_ERR_LIMIT if document or reader limits are exceeded.
 * @return #TLV_ERR_OUT_OF_MEMORY if node allocation fails.
 * @return Any other Tree Reader error, propagated unchanged.
 * @note On terminal traversal/build failure all unfinished nodes are released.
 *       Only NEED_MORE_DATA is resumable. The cursor is not rolled back on failure.
 */
TLV_API tlv_result_t tlv_document_builder_consume(tlv_document_builder_t* builder,
                                                  tlv_document_t** document, size_t* error_offset,
                                                  tlv_reader_diagnostic_t* diagnostic);

/**
 * @brief Destroy a builder and discard any unfinished document.
 * @param[in] builder Builder to release; NULL is ignored. A transferred document
 *                    is unaffected. Does not free the borrowed reader or its input.
 */
TLV_API void tlv_document_builder_free(tlv_document_builder_t* builder);

/**
 * @brief Fills options with the given format and the default limits.
 *
 * Sets `max_depth` to #TLV_TREE_DEFAULT_DEPTH, `max_elements` to
 * #TLV_DOCUMENT_DEFAULT_MAX_ELEMENTS and the allocator to `NULL`.
 *
 * @param[out] options Options to initialize.
 * @param[in]  format  Format; borrowed.
 *
 * @return #TLV_OK on success.
 * @return #TLV_ERR_NULL_ARG if `options` is `NULL`, or `format` cannot both
 *         read and write.
 */
TLV_API tlv_result_t tlv_document_options_init(tlv_document_options_t* options,
                                               const tlv_format_t* format);

/**
 * @brief Creates an empty document.
 *
 * @param[in]  options  Format descriptor and limits; copied.
 * @param[out] document Receives the document; free it with tlv_document_free(). Set to
 *                      `NULL` on failure.
 *
 * @return #TLV_OK on success.
 * @return #TLV_ERR_NULL_ARG for a `NULL` argument, an unusable format or an allocator that
 *         lacks a callback.
 * @return #TLV_ERR_OUT_OF_MEMORY if memory is exhausted.
 */
TLV_API tlv_result_t tlv_document_create(const tlv_document_options_t* options,
                                         tlv_document_t** document);

/**
 * @brief Parses encoded elements into a new owned document.
 *
 * Reads the whole input with the reader format. Values of tags that
 * `is_constructed` accepts are parsed as nested elements, up to `max_depth`.
 * Tags and values are copied, so the input may be released or reused after the call.
 * Empty input gives an empty document.
 *
 * @param[in]  data         Encoded input. May be `NULL` only when `size` is zero.
 * @param[in]  size         Input size in bytes.
 * @param[in]  options      Format descriptor and limits; copied.
 * @param[out] document     Receives the document; free it with tlv_document_free(). Set to
 *                          `NULL` on failure.
 * @param[out] error_offset Optional. On traversal or node creation failure, receives the
 *                          offending element's absolute offset; unchanged on success or
 *                          failure before traversal starts.
 *
 * @return #TLV_OK on success.
 * @return Any error of tlv_document_create().
 * @return #TLV_ERR_LIMIT if the depth or element limit is exceeded.
 * @return Any reader error, propagated unchanged.
 *
 * @note Nothing is retained on failure: everything allocated so far is released.
 */
TLV_API tlv_result_t tlv_document_parse(const uint8_t* data, size_t size,
                                        const tlv_document_options_t* options,
                                        tlv_document_t** document, size_t* error_offset);

/**
 * @brief Frees a document and every node in it.
 *
 * @param[in] document Document to free. `NULL` is ignored.
 *
 * @warning Invalidates all node pointers, and the tag and value pointers, of the document.
 */
TLV_API void tlv_document_free(tlv_document_t* document);

/**
 * @brief Returns the number of elements in the document, including nested ones.
 *
 * @param[in] document Document to query.
 *
 * @return The element count, or zero for `NULL`.
 */
TLV_API size_t tlv_document_count(const tlv_document_t* document);

/**
 * @name Navigation
 * Nodes form a tree. Top-level nodes have no parent, and the children of a node are in
 * encoding order. Every function returns `NULL` when there is no such node, and for a `NULL`
 * argument.
 * @{
 */

/** @brief Returns the first top-level node. */
TLV_API tlv_node_t* tlv_document_first(const tlv_document_t* document);

/** @brief Returns the first child of a constructed node. */
TLV_API tlv_node_t* tlv_node_first_child(const tlv_node_t* node);

/** @brief Returns the next sibling of a node. */
TLV_API tlv_node_t* tlv_node_next(const tlv_node_t* node);

/** @brief Returns the parent of a node, or `NULL` for a top-level node. */
TLV_API tlv_node_t* tlv_node_parent(const tlv_node_t* node);

/**
 * @brief Finds the first direct child with a tag.
 *
 * @param[in] document Document that owns `parent`.
 * @param[in] parent   Node whose children are searched, or `NULL` for the top level.
 * @param[in] tag      Tag to look for, compared by contents like tlv_tag_equal().
 *
 * @return The first matching child in encoding order, or `NULL`.
 */
TLV_API tlv_node_t* tlv_document_find(const tlv_document_t* document, const tlv_node_t* parent,
                                      tlv_tag_t tag);

/** @brief Returns the next sibling that has the same tag as `node`, or `NULL`. */
TLV_API tlv_node_t* tlv_node_next_same_tag(const tlv_node_t* node);

/** @brief Callback for a matching Document Node.
 * @param node Borrowed matching node.
 * @param context Caller context.
 * @return CONTINUE, STOP or ERROR following the Visitor contract.
 */
typedef tlv_visit_result_t (*tlv_document_query_visitor_t)(tlv_node_t* node, void* context);

/** @brief Visit every path match in Document order using the canonical Query matcher.
 * @param document Borrowed Document.
 * @param query Parsed Query, borrowed for the call.
 * @param visitor Required callback.
 * @param context Optional caller context.
 * @return OK on exhaustion or STOP, NULL_ARG for missing arguments, Query validation
 * errors, or VISITOR for ERROR or an unknown callback result.
 * @warning Do not mutate or destroy the Document during traversal. Nodes borrow it.
 * Callback effects are not rolled back on failure.
 * @note Never allocates.
 */
TLV_API tlv_result_t tlv_document_query_visit(const tlv_document_t* document,
                                              const tlv_query_t* query,
                                              tlv_document_query_visitor_t visitor, void* context);

/** @brief Discover caller storage for complete constructed Values in compiled Query execution.
 * @param[in] document Live owning Document.
 * @param[in,out] staging Caller-owned Tree Writer frames/output/scratch, disjoint
 * from Document and result Value storage. Short storage reports Writer requirements;
 * resize explicitly and repeat discovery from the start.
 * @param[out] bytes Sum of encoded child sequences for all constructed nodes.
 * @return OK, NULL argument, overflow or original Writer sizing error.
 * @note No allocation or wire parsing. Worst-case sizing is quadratic in node count;
 * it is separate from the execution work budget. Primitive Values borrow the Document.
 * Source offsets are unavailable. */
TLV_API tlv_result_t tlv_document_query_value_size(const tlv_document_t* document,
                                                   tlv_tree_writer_workspace_t* staging,
                                                   size_t* bytes);

/** @brief Evaluate a compiled program over Document nodes using a fresh retained execution.
 * @param[in] document Live Document; must remain unchanged through result consumption.
 * @param[in,out] exec Fresh execution created with tlv_query_eval_init, including D plans.
 * @param[in] context Optional node in this Document; NULL selects its virtual root.
 * @param[in,out] values Caller storage for constructed Values, alive until execution reset.
 * @param[in] capacity Available Value bytes, discovered with query_value_size.
 * @param[in,out] staging Caller-owned bounded Tree Writer frames/output/scratch.
 * Must be disjoint from values, Query workspace and Document storage.
 * @param[out] diagnostic Optional error detail; Source locations are unavailable.
 * @return OK with finalized nodes/scalar; capacity, depth, candidate, work or original
 * Writer/evaluation errors. A foreign context or used execution is invalid.
 * @note No allocation. Uses public node navigation and the shared Query VM. Values of
 * constructed nodes are regenerated by the Document Writer into explicit caller storage.
 * Encoding follows current Document semantics, including edits, rather than preserving
 * historical wire spellings. Workspace retains one descriptor per node and bounded VM sets.
 * Work charges conservatively account for repeated Writer subtree walks and bytes;
 * evaluation can be superlinear and terminates on the configured work budget.
 * Failure after execution begins is terminal until reset; no results have been emitted. */
TLV_API tlv_result_t tlv_document_query_evaluate(const tlv_document_t* document,
                                                 tlv_query_exec_t* exec, const tlv_node_t* context,
                                                 void* values, size_t capacity,
                                                 tlv_tree_writer_workspace_t* staging,
                                                 tlv_query_diagnostic_t* diagnostic);

/** @brief Pull the next finalized unique node handle in current Document preorder.
 * @param[in,out] exec Successfully evaluated Document node execution.
 * @param[out] node Borrowed node; unchanged on exhaustion or error.
 * @return OK, END_OF_BUFFER, NULL argument or invalid execution state.
 * @note Document and Value storage must remain alive and unchanged. First is one pull;
 * all is repeated pulls. Iteration allocates nothing and also works without Source. */
TLV_API tlv_result_t tlv_document_query_next(tlv_query_exec_t* exec, tlv_node_t** node);

/** @brief Visit remaining finalized Document results; STOP resumes after the delivered node.
 * @param[in,out] exec Successfully evaluated Document node execution.
 * @param[in] visitor Required callback; must not edit the Document.
 * @param[in] context Optional callback context.
 * @return OK on exhaustion/STOP, VISITOR on callback error (terminal), or pull errors.
 * @warning Previously delivered callbacks are never rolled back. */
TLV_API tlv_result_t tlv_document_query_program_visit(tlv_query_exec_t* exec,
                                                      tlv_document_query_visitor_t visitor,
                                                      void* context);

/**
 * @brief Finds the first element addressed by a path query.
 *
 * Uses the query language of tlv_query_parse(), for example `6F/A5/50`: the first tag names
 * a top-level element, each further tag one of its direct children. The elements
 * addressed by the query are searched in document order, and a step that leads to a dead end
 * does not hide a later match.
 *
 * @param[in] document Document to search.
 * @param[in] query    Parsed query.
 *
 * @return The first addressed node, or `NULL` if none, or if an argument is `NULL` or the
 *         query is empty.
 */
TLV_API tlv_node_t* tlv_document_find_path(const tlv_document_t* document,
                                           const tlv_query_t* query);

/** @} */

/**
 * @name Reading a node
 * @{
 */

/**
 * @brief Returns the tag of a node.
 *
 * @param[in] node Node to read.
 *
 * @return A tag that borrows the node's storage, or the empty tag for `NULL`.
 */
TLV_API tlv_tag_t tlv_node_tag(const tlv_node_t* node);

/** @brief Returns nonzero when the node's value holds nested elements, zero otherwise and for
 * `NULL`. */
TLV_API int tlv_node_is_constructed(const tlv_node_t* node);

/**
 * @brief Returns the value bytes of a primitive node.
 *
 * @param[in] node Node to read.
 *
 * @return A pointer that borrows the node's storage, or `NULL` when the value is empty, when
 *         the node is constructed (read its children instead) or when `node` is `NULL`.
 *         Use tlv_node_value_size() for the length.
 */
TLV_API const uint8_t* tlv_node_value_data(const tlv_node_t* node);

/** @brief Returns the length of a primitive node's value; zero for a constructed node and for
 * `NULL`. */
TLV_API size_t tlv_node_value_size(const tlv_node_t* node);

/** @} */

/**
 * @name Modification
 * Every modification either succeeds completely or leaves the document unchanged.
 * @{
 */

/**
 * @brief Replaces the value of a node.
 *
 * For a primitive node the bytes are copied. For a constructed node the bytes are parsed as
 * nested elements with the document's reader format, and replace all children, as if the
 * node had been read from such an encoding.
 *
 * @param[in,out] node   Node to change.
 * @param[in]     value  New value bytes; copied. May be `NULL` only when `length` is zero.
 * @param[in]     length Value length in bytes.
 *
 * @return #TLV_OK on success.
 * @return #TLV_ERR_NULL_ARG for a `NULL` node, or a `NULL` value with a nonzero length.
 * @return #TLV_ERR_LIMIT if the depth or element limit would be exceeded.
 * @return #TLV_ERR_OUT_OF_MEMORY if memory is exhausted.
 * @return Any reader error for a constructed node's value.
 *
 * @warning Invalidates the previous value pointer of the node, and for a constructed node
 *          every child pointer.
 */
TLV_API tlv_result_t tlv_node_set_value(tlv_node_t* node, const uint8_t* value, size_t length);

/**
 * @brief Inserts a new element.
 *
 * The tag and value are copied. As with tlv_node_set_value(), the value of a tag that
 * `is_constructed` accepts is parsed as nested elements. The tag is checked
 * with the writer format, so a tag it cannot write is rejected here.
 *
 * @param[in,out] document Document to change.
 * @param[in]     parent   Constructed node that receives the element, or `NULL` for the top level.
 * @param[in]     before   Existing child of `parent` that the new node precedes, or `NULL` to
 *                         append at the end.
 * @param[in]     tag      Tag of the new element.
 * @param[in]     value    Value bytes. May be `NULL` only when `length` is zero.
 * @param[in]     length   Value length in bytes.
 * @param[out]    node     Optional. Receives the new node.
 *
 * @return #TLV_OK on success.
 * @return #TLV_ERR_NULL_ARG for a `NULL` document, a `NULL` value with a nonzero length, or a
 *         tag with a `NULL` pointer and nonzero size.
 * @return #TLV_ERR_INVALID_ARG if `parent` is primitive or belongs to another document, or
 *         `before` is not a child of `parent`.
 * @return #TLV_ERR_LIMIT if the depth or element limit would be exceeded.
 * @return #TLV_ERR_OUT_OF_MEMORY if memory is exhausted.
 * @return Any writer format error for the tag, or reader error for a constructed value.
 */
TLV_API tlv_result_t tlv_document_insert(tlv_document_t* document, tlv_node_t* parent,
                                         const tlv_node_t* before, tlv_tag_t tag,
                                         const uint8_t* value, size_t length, tlv_node_t** node);

/**
 * @brief Removes a node and all of its descendants from its document.
 *
 * @param[in] node Node to erase. `NULL` is ignored.
 *
 * @warning Invalidates `node` and every node below it.
 */
TLV_API void tlv_node_erase(tlv_node_t* node);

/** @} */

/**
 * @name Encoding
 * Encoding and exact measurement consume a preorder source through Tree Writer.
 * Constructed Values are generated from children using the destination Format;
 * content-dependent measurement receives actual encoded child bytes.
 * @{
 */

/**
 * @brief Computes the encoded size of a whole document.
 *
 * Uses iterative Tree Writer measurement and temporary storage from the Document
 * allocator. Measurement stages the complete encoding, so encoder errors can also
 * be reported. Storage comprises an O(depth) stack, staged output and shared scratch;
 * there is no separate buffer for each constructed node.
 *
 * @param[in]  document Document to size.
 * @param[out] size     Receives the size in bytes. Unchanged on failure.
 *
 * @return #TLV_OK on success.
 * @return #TLV_ERR_NULL_ARG for a `NULL` argument.
 * @return #TLV_ERR_OUT_OF_MEMORY if temporary traversal storage cannot be allocated.
 * @return Any writer format error, such as #TLV_ERR_INVALID_LENGTH for a length the format
 *         cannot represent.
 */
TLV_API tlv_result_t tlv_document_encoded_size(const tlv_document_t* document, size_t* size);

/**
 * @brief Encodes a whole document into caller-owned memory.
 *
 * On insufficient capacity `*written` receives the required size, nothing is written and the
 * result is #TLV_ERR_BUFFER_TOO_SHORT, as for tlv_write().
 *
 * @param[in]  document Document to encode.
 * @param[out] data     Destination. May be `NULL` only when `capacity` is zero.
 * @param[in]  capacity Destination capacity in bytes.
 * @param[out] written  Receives the number of bytes written, or the required size.
 *
 * @return #TLV_OK on success.
 * @return #TLV_ERR_NULL_ARG for a `NULL` argument.
 * @return #TLV_ERR_BUFFER_TOO_SHORT if `capacity` is insufficient.
 * @return #TLV_ERR_OUT_OF_MEMORY if memory for a temporary buffer is exhausted.
 * @return Any writer format error.
 *
 * @warning A failure other than the capacity check may leave `data` modified.
 */
TLV_API tlv_result_t tlv_document_encode(const tlv_document_t* document, uint8_t* data,
                                         size_t capacity, size_t* written);

/**
 * @brief Computes the encoded size of one element with its descendants.
 *
 * Follows the rules of tlv_document_encoded_size().
 *
 * @param[in]  node Node to size.
 * @param[out] size Receives the size in bytes. Unchanged on failure.
 */
TLV_API tlv_result_t tlv_node_encoded_size(const tlv_node_t* node, size_t* size);

/**
 * @brief Encodes one element with its descendants.
 *
 * Follows the rules of tlv_document_encode().
 *
 * @param[in]  node     Node to encode.
 * @param[out] data     Destination. May be `NULL` only when `capacity` is zero.
 * @param[in]  capacity Destination capacity in bytes.
 * @param[out] written  Receives the number of bytes written, or the required size.
 */
TLV_API tlv_result_t tlv_node_encode(const tlv_node_t* node, uint8_t* data, size_t capacity,
                                     size_t* written);

/**
 * @brief Compute document size with an explicit destination Format.
 * @param[in] document Required immutable document.
 * @param[in] format Required writable Format and context, borrowed for this call.
 * @param[out] size Exact encoded size; unchanged on failure.
 * @return Same results as tlv_document_encoded_size(); #TLV_ERR_INVALID_TAG if
 *         destination constructed classification differs from the stored topology.
 * @note The document's original Format and nodes remain unchanged. Identifiers
 *       are never remapped. The Format need not support decoding. Deterministic
 *       callbacks may be replayed while Document grows its staging workspace.
 */
TLV_API tlv_result_t tlv_document_encoded_size_as(const tlv_document_t* document,
                                                  const tlv_format_t* format, size_t* size);

/**
 * @brief Encode a document using an explicit compatible destination Format.
 * @param[in] document Required immutable document.
 * @param[in] format Destination as for tlv_document_encoded_size_as().
 * @param[out] data Caller-owned destination; NULL only when capacity is zero.
 * @param[in] capacity Available destination bytes.
 * @param[out] written Encoded size on success or required size on capacity failure.
 * @return Same results and output guarantees as tlv_document_encode(), plus
 *         #TLV_ERR_INVALID_TAG for incompatible constructed classification.
 * @note Uses the Document allocator. Wire rules come exclusively from Format
 *       through Tree Writer; the original document and its Format are unchanged.
 */
TLV_API tlv_result_t tlv_document_encode_as(const tlv_document_t* document,
                                            const tlv_format_t* format, uint8_t* data,
                                            size_t capacity, size_t* written);

/**
 * @brief Measure one node and its descendants using a destination Format.
 * @param[in] node Required root of the subtree; siblings are excluded.
 * @param[in] format Destination as for tlv_document_encoded_size_as().
 * @param[out] size Exact encoded subtree size; unchanged on failure.
 * @return Same results as tlv_document_encoded_size_as().
 */
TLV_API tlv_result_t tlv_node_encoded_size_as(const tlv_node_t* node, const tlv_format_t* format,
                                              size_t* size);

/**
 * @brief Encode one node and its descendants using a destination Format.
 * @param[in] node Required subtree root; siblings are excluded.
 * @param[in] format Destination as for tlv_document_encoded_size_as().
 * @param[out] data Caller-owned destination; NULL only when capacity is zero.
 * @param[in] capacity Available destination bytes.
 * @param[out] written Encoded size on success or required size on capacity failure.
 * @return Same results and output guarantees as tlv_document_encode_as().
 */
TLV_API tlv_result_t tlv_node_encode_as(const tlv_node_t* node, const tlv_format_t* format,
                                        uint8_t* data, size_t capacity, size_t* written);

/** @} */

#ifdef __cplusplus
}
#endif

/** @} */

#endif /* OPENTLV_DOCUMENT_H */
