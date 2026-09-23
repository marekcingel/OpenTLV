#ifndef OPENTLV_DOCUMENT_H
#define OPENTLV_DOCUMENT_H

#include "tlv/export.h"
#include "tlv/error.h"
#include "tlv/format.h"
#include "tlv/query/query.h"
#include "tlv/reader/walker.h"
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
 * predicate are passed in #tlv_document_options_t, exactly as for
 * tlv_walk_tree(). Nothing in the allocation-free core depends on it. It is
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
 * structure, but the formats, the format contexts and the allocator context are
 * borrowed and must outlive the document.
 */
typedef struct tlv_document_options {
    /** Reader format used to parse input and values. Required. */
    const tlv_reader_format_t* reader_format;
    /** Writer format used to encode the document. Required. */
    const tlv_writer_format_t* writer_format;
    /**
     * Predicate receiving `reader_format->context` that tells which tags hold nested
     * elements, or `NULL` to keep every value opaque. Its answer is taken when a node is
     * created and stays with the node.
     */
    tlv_is_constructed_fn is_constructed;
    /**
     * Maximum nesting depth, `0..TLV_WALK_MAX_DEPTH`; top-level elements have depth zero and an
     * element that would lie deeper is rejected with #TLV_ERR_LIMIT.
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
 * @brief Fills options with the given formats and the default limits.
 *
 * Sets `max_depth` to #TLV_WALK_MAX_DEPTH, `max_elements` to
 * #TLV_DOCUMENT_DEFAULT_MAX_ELEMENTS and the allocator to `NULL`.
 *
 * @param[out] options        Options to initialize.
 * @param[in]  reader_format  Reader format; borrowed.
 * @param[in]  writer_format  Writer format; borrowed.
 * @param[in]  is_constructed Nesting predicate, or `NULL` for opaque values.
 *
 * @return #TLV_OK on success.
 * @return #TLV_ERR_NULL_ARG if `options` or a format is `NULL`, or a format lacks a
 *         required callback.
 */
TLV_API tlv_result_t tlv_document_options_init(tlv_document_options_t* options,
                                               const tlv_reader_format_t* reader_format,
                                               const tlv_writer_format_t* writer_format,
                                               tlv_is_constructed_fn is_constructed);

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
 * @return #TLV_ERR_LIMIT if `max_depth` exceeds #TLV_WALK_MAX_DEPTH.
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
 * @param[out] error_offset Optional. On failure of the input, receives the absolute offset of
 *                          the offending element; unchanged otherwise.
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
 * Encoding runs every element through the writer format. Sizes and bytes agree with
 * tlv_encoded_size() and tlv_write(), and constructed values are written from their children,
 * so no length is stored that could go stale.
 * @{
 */

/**
 * @brief Computes the encoded size of a whole document.
 *
 * @param[in]  document Document to size.
 * @param[out] size     Receives the size in bytes. Unchanged on failure.
 *
 * @return #TLV_OK on success.
 * @return #TLV_ERR_NULL_ARG for a `NULL` argument.
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

/** @} */

#ifdef __cplusplus
}
#endif

/** @} */

#endif /* OPENTLV_DOCUMENT_H */
