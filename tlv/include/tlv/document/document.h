// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#ifndef OPENTLV_DOCUMENT_H
#define OPENTLV_DOCUMENT_H

#include "tlv/export.h"
#include "tlv/error.h"
#include "tlv/format.h"
#include "tlv/config.h"
#if OPENTLV_QUERY
#include "tlv/query/query.h"
#endif
#if OPENTLV_READER
#include "tlv/reader/visitor.h"
#endif
#include "tlv/tag.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Opaque compiled Query execution, defined in tlv/query/program.h. */
struct tlv_query_exec;
/** @brief Query diagnostic, defined in tlv/query/program.h. */
struct tlv_query_diagnostic;
/** @brief Caller Writer staging, defined in tlv/writer/tree.h. */
struct tlv_tree_writer_workspace;

/**
 * @file
 * @ingroup document
 * @brief Optional mutable TLV document that owns its data and can be modified and encoded again.
 *
 * The reader, writer and traversal APIs are zero-copy and never allocate.
 * This component owns a mutable tree that can be built programmatically.
 * The Reader integration tlv_document_parse() copies wire input into nodes;
 * the Writer integration tlv_document_encode() serializes the current tree.
 *
 * The owned tree is independent of Reader, Writer and Query. Wire import
 * requires OPENTLV_READER; encoding requires OPENTLV_WRITER; path matching
 * requires OPENTLV_QUERY. Compiled Document Query currently requires Reader
 * and Writer as well. The Format and nesting predicate are supplied through
 * #tlv_document_options_t. Read/write callbacks are needed only by wire
 * operations. Nothing in the allocation-free core depends on Document. It is
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
 * @note The Format need not provide read/write callbacks for programmatic trees.
 * Nonempty constructed wire values require OPENTLV_READER; without it, insert
 * and set_value return TLV_ERR_UNSUPPORTED_TYPE without changing the tree.
 *
 * Initialize with tlv_document_options_init(). The document copies this
 * structure, but the format, the format's context and the allocator context are
 * borrowed and must outlive the document.
 * @see @docs{guides/memory,format context ownership and lifetime}
 */
typedef struct tlv_document_options {
    /**
     * Format used to parse input and values and to encode the document.
     * Required; read/write callbacks are only required for wire integration, see
     * tlv_format_can_read() and tlv_format_can_write(). `format->is_constructed` tells which tags
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
    /** Retain original source locations during parse/build (default zero).
     * Adds per-node storage, but never borrows input bytes. Inserted/replacement
     * nodes have no location. Successful edits invalidate the edited node and
     * its ancestors; unaffected nodes retain their original input coordinates. */
    int retain_source_locations;
} tlv_document_options_t;

/** @brief Original input coordinates, independent of the input buffer's lifetime.
 * These are not offsets in a future serialization. Zero is a valid offset or
 * header size; consult the presence flags. No original bytes are retained. */
typedef struct tlv_document_source_location {
    size_t offset;       /**< Absolute element start in the original Reader input. */
    size_t header_size;  /**< Original encoded header length. */
    int has_offset;      /**< Nonzero when the original element offset is known. */
    int has_header_size; /**< Nonzero when the original header length is known. */
} tlv_document_source_location_t;

/** @brief An owned mutable TLV document. Opaque; create with tlv_document_create() or
 * tlv_document_parse(). */
typedef struct tlv_document tlv_document_t;

/** @brief One element of a document. Opaque; owned by its document. */
typedef struct tlv_node tlv_node_t;

/** @brief Read a copy of a node's optional original source location.
 * @param node Live node, or NULL for an unavailable location.
 * @return Coordinates with explicit presence flags; all zero when unavailable.
 * @note Value replacement invalidates this node and its ancestors. Insert/erase
 * invalidates ancestors only. Failed edits preserve locations. Replacement
 * children and inserted nodes never acquire locations from mutation buffers.
 * Unaffected siblings keep their original coordinates even if encoding shifts.
 */
TLV_API tlv_document_source_location_t tlv_node_source_location(const tlv_node_t* node);

/** @brief Observe the whole-Document mutation revision; NULL returns zero.
 * @param document Live Document, borrowed for the call.
 * @return Revision increased by every successful insert, erase or Value replacement.
 * @note Failed edits preserve revision. This is not a destruction-safe handle;
 * callers must retain the Document owner. Concurrent mutation requires external locking.
 * Query callbacks reject fallible edits with INVALID_STATE. Void erase/free requests
 * are deferred until the outermost Query callback on this Document returns;
 * that visit ends with INVALID_STATE. Concurrent mutation requires exclusive access
 * even when requested from a callback. Revisions wrap after UINT64_MAX edits. */
TLV_API uint64_t tlv_document_revision(const tlv_document_t* document);

/** @brief Observe the whole-Document Node retirement epoch; NULL returns zero.
 *
 * @param document Live Document, borrowed for the call, or NULL.
 * @return Epoch initially zero, increased once by each successful edit that retires
 * at least one previously published Node: erase or constructed Value replacement
 * with existing children. Insertions, primitive replacements, replacements of
 * constructed Nodes without existing children, and failed individual edits preserve the epoch.
 * @note This constant-time query allocates nothing. Deferred Query-callback
 * erasure advances the epoch only when it commits. Batch edits retain increments
 * from earlier committed operations if a later operation fails.
 * This epoch detects potentially stale Node addresses, not changes to borrowed
 * Value bytes; use tlv_document_revision() to observe every successful mutation.
 * It is not a destruction-safe handle or a synchronization primitive. Keep the
 * Document alive and provide exclusive access during mutation.
 * @note Epochs never wrap: each increment retires a distinct Node identity, and
 * identity exhaustion rejects further creation before identities can be reused.
 * @see tlv_document_node_identity for allocation-free stale-address validation. */
TLV_API uint64_t tlv_document_retire_epoch(const tlv_document_t* document);

/** @brief Check a possibly stale node address without dereferencing it.
 * @param document Live owning Document; caller must retain its lifetime.
 * @param node Address to locate, possibly erased or foreign.
 * @return Nonzero immutable identity within this Document, or zero when absent/NULL.
 * @note O(node count) scan, allocation-free. Identities are never reused, including
 * allocator address reuse; exhaustion rejects creation with LIMIT. Store identity
 * alongside an address to detect erase/replacement after the retirement epoch changes. */
TLV_API uint64_t tlv_document_node_identity(const tlv_document_t* document, const tlv_node_t* node);

/** @brief Read a live node's immutable Document-local identity in constant time.
 * @param node Live node or NULL; stale pointers are forbidden.
 * @return Nonzero identity, or zero for NULL.
 * @see tlv_document_node_identity for checking a possibly stale address. */
TLV_API uint64_t tlv_node_identity(const tlv_node_t* node);

#if OPENTLV_QUERY && OPENTLV_READER && OPENTLV_WRITER
/** @brief Completed Query selection edit operation. */
typedef enum tlv_document_query_edit_kind {
    TLV_DOCUMENT_QUERY_REMOVE,  /**< Erase selected roots; selected ancestors dominate descendants.
                                 */
    TLV_DOCUMENT_QUERY_REPLACE, /**< Replace Values; selected ancestors dominate descendants. */
    TLV_DOCUMENT_QUERY_INSERT_AFTER /**< Insert one sibling immediately after each selected target.
                                     */
} tlv_document_query_edit_kind_t;

/** @brief Edit an already finalized compiled Query selection, never an active traversal.
 * @param document Live mutable Document used by execution.
 * @param exec Finished node-result execution; all targets are collected before mutation.
 * @param kind Operation selector.
 * @param tag Insertion identifier; ignored by other operations.
 * @param value Replacement/insertion Value, copied before editing; ignored by removal.
 * @param size Value bytes.
 * @param targets Exclusive caller array of node pointers for the complete selection.
 * @param capacity Array entries; short storage leaves the cursor and targets unchanged,
 * permitting retry of the same completed execution with a larger target array.
 * @param applied Required output, initialized to zero; successful edited selected roots.
 * Targets and applied must not overlap each other or a used Value; such overlap
 * returns #TLV_ERR_INVALID_ARG before writes.
 * @return OK for no matches, or native error. Invalid operation/capacity/revision makes
 * no edits. Remove cannot fail after collection. Replace/insert commit in preorder,
 * stopping at first failure; previous successful edits remain, without rollback.
 * Tag framing, constructed Value syntax and every target's depth/count limits are
 * prevalidated before editing; their failure makes no tree changes. Allocation or
 * identity exhaustion can still cause partial application during commit.
 * @note Ancestor dominance is resolved before editing. Insertion includes every selected
 * node once and preserves original sibling order. Document allocator owns temporary Value
 * copies and normal inserted nodes. Native pointers borrow Document; keep it alive through
 * collection. Any successful edit invalidates the execution's whole-document revision.
 * REPLACE stores identical bytes on primitive targets but parses them as children on
 * constructed targets. Overlap filtering is O(target count * depth), allocation-free.
 * @return #TLV_ERR_INVALID_STATE during callbacks, for stale results or after result iteration has
 * begun.
 */
TLV_API tlv_result_t tlv_document_query_edit(tlv_document_t* document, struct tlv_query_exec* exec,
                                             tlv_document_query_edit_kind_t kind, tlv_tag_t tag,
                                             const uint8_t* value, size_t size,
                                             tlv_node_t** targets, size_t capacity,
                                             size_t* applied);

#endif

#if OPENTLV_READER
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
 * @return #TLV_ERR_INVALID_STATE for a non-fresh whole-stream cursor.
 * @return #TLV_ERR_INVALID_ARG for a format mismatch,
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
 * @return #TLV_ERR_INVALID_STATE if already completed or failed.
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

#endif

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
 * @return #TLV_ERR_NULL_ARG if `options` or `format` is `NULL`.
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
 * @return #TLV_ERR_NULL_ARG for a `NULL` argument or an allocator that
 *         lacks a callback.
 * @return #TLV_ERR_OUT_OF_MEMORY if memory is exhausted.
 */
TLV_API tlv_result_t tlv_document_create(const tlv_document_options_t* options,
                                         tlv_document_t** document);

#if OPENTLV_READER
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

#endif

/**
 * @brief Frees a document and every node in it.
 *
 * @param[in] document Document to free. `NULL` is ignored.
 *
 * @warning Invalidates all node pointers, and the tag and value pointers, of the document.
 * @note During a Query callback, destruction is deferred until the outermost visit
 * returns from its callback. That visit returns INVALID_STATE; do not use the owner
 * or any node after it returns. Repeated pending free requests release only once.
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

#if OPENTLV_QUERY
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
 * @return #TLV_ERR_INVALID_STATE if a callback requests deferred erasure or destruction.
 */
TLV_API tlv_result_t tlv_document_query_visit(const tlv_document_t* document,
                                              const tlv_query_t* query,
                                              tlv_document_query_visitor_t visitor, void* context);

#if OPENTLV_READER && OPENTLV_WRITER
/** @brief Discover the complete encoded snapshot size for compiled Document Query Values.
 * @param[in] document Live owning Document.
 * @param[in,out] staging Caller-owned Tree Writer frames/output/scratch, disjoint
 * from Document storage. Short storage reports Writer requirements; resize
 * explicitly and repeat discovery from the start.
 * @param[out] bytes Complete encoded Document size, not a sum of nested Values.
 * @return OK, NULL argument, overflow or original Writer sizing error.
 * @note No allocation. Encodes the Document once through the canonical Writer.
 * Discovery is outside the execution work budget. It is unnecessary when program
 * info reports constructed_values_required == 0. Output may be reused as the
 * evaluation snapshot. Include tlv/writer/tree.h for the workspace definition. */
TLV_API tlv_result_t tlv_document_query_value_size(const tlv_document_t* document,
                                                   struct tlv_tree_writer_workspace* staging,
                                                   size_t* bytes);

/** @brief Evaluate a compiled program over Document nodes using a fresh retained execution.
 * @param[in] document Live Document; must remain unchanged through result consumption.
 * @param[in,out] exec Fresh execution created with tlv_query_eval_init, including D plans.
 * @param[in] context Optional live node in this Document; NULL selects its virtual root.
 * Erased/stale pointers are forbidden. Ownership validation is O(1).
 * @param[in,out] values Complete encoded snapshot storage, alive until execution reset.
 * May reuse discovery staging.data. NULL/zero is sufficient when constructed
 * Values are not required by the compiled program.
 * @param[in] capacity Snapshot bytes, discovered with query_value_size when needed.
 * @param[in,out] staging Caller-owned bounded Tree Writer frames and closing scratch.
 * Output data/capacity are used only during discovery; evaluation writes directly
 * into values. Frames/scratch must be disjoint from values, Query and Document storage.
 * May be NULL when program info reports constructed_values_required == 0.
 * @param[out] diagnostic Optional error detail, with retained source offset when available.
 * @return OK with finalized nodes/scalar; capacity, depth, candidate, work or original
 * Writer/Reader/evaluation errors. A foreign context or used execution is invalid.
 * @note No allocation. Uses public node navigation and the shared Query VM. Programs
 * that may inspect constructed Values encode the Document once; canonical Reader
 * decoding maps nodes to slices of that snapshot. Other programs skip encoding entirely.
 * Encoding follows current Document semantics, including edits. Historical wire
 * spellings are not preserved. `@offset` and `@hlen` use optional retained original
 * locations; unavailable locations produce SOURCE diagnostics. They never refer to
 * the canonical Value snapshot. Work charges use visited events
 * and actual byte extents, independently of spare buffer capacity. General Writer
 * encoding and Query evaluation may still be superlinear on deeply nested inputs.
 * Failure after execution begins is terminal until reset; no results have been emitted.
 * During evaluation and result callbacks, replacement/insertion and nested traversal
 * on this Document are rejected. Erase/free requests are deferred until the enclosing
 * operation returns from its callbacks, then invalidate execution. Borrowed node and
 * Value spans remain alive during callbacks. Outside those operations the caller must
 * keep the Document alive; this API does not retain ownership or synchronize threads.
 * Include tlv/query/program.h and, when needed, tlv/writer/tree.h for type definitions.
 * @return #TLV_ERR_INVALID_STATE for used execution, callback reentrancy or callback invalidation.
 */
TLV_API tlv_result_t tlv_document_query_evaluate(const tlv_document_t* document,
                                                 struct tlv_query_exec* exec,
                                                 const tlv_node_t* context, void* values,
                                                 size_t capacity,
                                                 struct tlv_tree_writer_workspace* staging,
                                                 struct tlv_query_diagnostic* diagnostic);

/** @brief Pull the next finalized unique node handle in current Document preorder.
 * @param[in,out] exec Successfully evaluated Document node execution.
 * @param[out] node Borrowed node; unchanged on exhaustion or error.
 * @return OK, END_OF_BUFFER, NULL argument or invalid execution state/revision.
 * @note Document and Value storage must remain alive and unchanged. First is one pull;
 * all is repeated pulls. Any successful Document edit rejects subsequent pulls
 * before dereferencing retained nodes. Iteration allocates nothing and also works
 * without Source. Keep the native Document alive; revision is not a destruction token.
 * @return #TLV_ERR_INVALID_STATE for unfinished/failed execution, reentrancy or a stale Document
 * revision.
 */
TLV_API tlv_result_t tlv_document_query_next(struct tlv_query_exec* exec, tlv_node_t** node);

/** @brief Visit remaining finalized Document results; STOP resumes after the delivered node.
 * @param[in,out] exec Successfully evaluated Document node execution.
 * @param[in] visitor Required callback; must not edit the Document.
 * @param[in] context Optional callback context.
 * @return OK on exhaustion/STOP, VISITOR on callback error (terminal), or pull errors.
 * @warning Previously delivered callbacks are never rolled back. Erase/free requests
 * are deferred until callback return and invalidate this execution. Same-execution
 * feed, finish, reset, bind and nested visits are rejected without altering it.
 * @return #TLV_ERR_INVALID_STATE for callback reentrancy, invalidated results or deferred mutation.
 */
TLV_API tlv_result_t tlv_document_query_program_visit(struct tlv_query_exec* exec,
                                                      tlv_document_query_visitor_t visitor,
                                                      void* context);

#endif

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

#endif

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
 * @return #TLV_ERR_INVALID_STATE during a Query callback.
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
 * @return #TLV_ERR_INVALID_STATE during a Query callback.
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
 * @note During a Query callback, erase is deferred until the outermost visit returns
 * from its callback, and that visit returns INVALID_STATE. Pending ancestor erasure
 * dominates descendant requests; all borrowed nodes remain alive inside the callback.
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

#if OPENTLV_WRITER
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

#endif

/** @} */

#ifdef __cplusplus
}
#endif

/** @} */

#endif /* OPENTLV_DOCUMENT_H */
