// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv/document/document.h"
#include "tlv/size.h"
#include "document_internal.h"
#include "tlv/defaults.h"
#if OPENTLV_READER
#include "tlv/reader/tree.h"
#endif
#if OPENTLV_WRITER
#include "tlv/writer/tree.h"
#endif
#include <stdlib.h>
#include <string.h>
#include <assert.h>

/* ---- Memory ---------------------------------------------------------------------------- */

static void* default_allocate(void* context, size_t size) {
    (void)context;
    return malloc(size);
}

static void default_release(void* context, void* memory) {
    (void)context;
    free(memory);
}

void* document_memory_allocate(const tlv_document_t* document, size_t size) {
    return document->allocator.allocate(document->allocator.context, size);
}

void document_memory_release(const tlv_document_t* document, void* memory) {
    if (memory) document->allocator.release(document->allocator.context, memory);
}

/* ---- Nodes ----------------------------------------------------------------------------- */

static const uint8_t* node_tag_data(const tlv_node_t* node) {
    return (const uint8_t*)(node + 1) + (node->document->options.retain_source_locations
                                             ? sizeof(tlv_document_source_location_t)
                                             : 0);
}

tlv_document_source_location_t* document_node_location(tlv_node_t* node) {
    return node && node->document->options.retain_source_locations
               ? (tlv_document_source_location_t*)(node + 1)
               : NULL;
}

tlv_document_source_location_t tlv_node_source_location(const tlv_node_t* node) {
    tlv_document_source_location_t empty = {0};
    if (!node || !node->document->options.retain_source_locations) return empty;
    return *(const tlv_document_source_location_t*)(node + 1);
}

static void invalidate_locations(tlv_node_t* node) {
    if (!node || !node->document->options.retain_source_locations) return;
    for (; node; node = node->parent)
        memset(document_node_location(node), 0, sizeof(tlv_document_source_location_t));
}

tlv_tag_t document_node_tag(const tlv_node_t* node) {
    return node->tag_size ? tlv_tag(node_tag_data(node), node->tag_size) : tlv_tag(NULL, 0);
}

static tlv_node_t** list_first(tlv_document_t* document, tlv_node_t* parent) {
    return parent ? &parent->first : &document->first;
}

static tlv_node_t** list_last(tlv_document_t* document, tlv_node_t* parent) {
    return parent ? &parent->last : &document->last;
}

/* Inserts an unlinked node into a child list; `before` NULL appends. */
static void node_link(tlv_document_t* document, tlv_node_t* parent, tlv_node_t* before,
                      tlv_node_t* node) {
    tlv_node_t** first = list_first(document, parent);
    tlv_node_t** last = list_last(document, parent);
    node->parent = parent;
    if (before) {
        node->next = before;
        node->prev = before->prev;
        if (before->prev)
            before->prev->next = node;
        else
            *first = node;
        before->prev = node;
    } else {
        node->prev = *last;
        node->next = NULL;
        if (*last)
            (*last)->next = node;
        else
            *first = node;
        *last = node;
    }
}

static void node_unlink(tlv_node_t* node) {
    tlv_document_t* document = node->document;
    tlv_node_t** first = list_first(document, node->parent);
    tlv_node_t** last = list_last(document, node->parent);
    if (node->prev)
        node->prev->next = node->next;
    else
        *first = node->next;
    if (node->next)
        node->next->prev = node->prev;
    else
        *last = node->prev;
    node->parent = node->prev = node->next = NULL;
}

/* Parent links provide iterative traversal without a depth-dependent C stack. */
static const tlv_node_t* subtree_next(const tlv_node_t* node, const tlv_node_t* root) {
    if (node->first) return node->first;
    while (node != root && !node->next) node = node->parent;
    return node == root ? NULL : node->next;
}

static size_t subtree_size(const tlv_node_t* node) {
    size_t total = 0;
    const tlv_node_t* current;
    for (current = node; current; current = subtree_next(current, node)) ++total;
    return total;
}

static void free_subtree(tlv_node_t* root) {
    tlv_node_t* node = root;
    while (node) {
        if (node->first) {
            node = node->first;
        } else {
            tlv_node_t* parent = node == root ? NULL : node->parent;
            if (parent) parent->first = node->next;
            document_memory_release(node->document, node->value);
            document_memory_release(node->document, node);
            node = parent;
        }
    }
}

static void free_children(tlv_node_t* node) {
    tlv_node_t* child = node->first;
    while (child) {
        tlv_node_t* next = child->next;
        free_subtree(child);
        child = next;
    }
    node->first = node->last = NULL;
}

/* Removes and frees every child of `parent` (NULL: the top level), including their count. */
static void discard_children(tlv_document_t* document, tlv_node_t* parent) {
    tlv_node_t* child = *list_first(document, parent);
    while (child) {
        tlv_node_t* next = child->next;
        document->count -= subtree_size(child);
        free_subtree(child);
        child = next;
    }
    *list_first(document, parent) = *list_last(document, parent) = NULL;
}

static size_t node_depth(const tlv_node_t* node) {
    size_t depth = 0;
    for (; node->parent; node = node->parent) ++depth;
    return depth;
}

static uint8_t* copy_bytes(const tlv_document_t* document, const uint8_t* data, size_t size) {
    uint8_t* copy;
    if (!size) return NULL;
    copy = (uint8_t*)document_memory_allocate(document, size);
    if (copy) memcpy(copy, data, size);
    return copy;
}

/* ---- Parsing --------------------------------------------------------------------------- */

void document_set_offset(size_t* out, size_t offset) {
    if (out) *out = offset;
}

/*
 * Creates one owned node; constructed children are supplied by the Tree Reader consumer.
 */
tlv_result_t document_create_node(tlv_document_t* document, tlv_node_t* parent, tlv_tag_t tag,
                                  const uint8_t* value, size_t length, int constructed,
                                  size_t depth, size_t element_offset, size_t* error_offset,
                                  tlv_node_t** created) {
    tlv_node_t* node;
    if (depth > document->options.max_depth || document->count >= document->options.max_elements) {
        document_set_offset(error_offset, element_offset);
        return TLV_ERR_LIMIT;
    }
    size_t node_size =
        sizeof *node +
        (document->options.retain_source_locations ? sizeof(tlv_document_source_location_t) : 0);
    if (tag.size > SIZE_MAX - node_size) return TLV_ERR_OUT_OF_MEMORY;
    if (document->next_identity == UINT64_MAX) return TLV_ERR_OVERFLOW;
    node = (tlv_node_t*)document_memory_allocate(document, node_size + tag.size);
    if (!node) return TLV_ERR_OUT_OF_MEMORY;
    memset(node, 0, node_size);
    node->document = document;
    node->identity = ++document->next_identity;
    node->tag_size = tag.size;
    if (tag.size) memcpy((void*)node_tag_data(node), tag.data, tag.size);
    node->constructed = constructed;
    if (!node->constructed && length) {
        node->value = copy_bytes(document, value, length);
        if (!node->value) {
            document_memory_release(document, node);
            return TLV_ERR_OUT_OF_MEMORY;
        }
        node->value_size = length;
    }
    node_link(document, parent, NULL, node);
    ++document->count;
    *created = node;
    return TLV_OK;
}

#if !OPENTLV_READER
tlv_result_t document_parse_list(tlv_document_t* document, tlv_node_t* parent, const uint8_t* data,
                                 size_t size, size_t depth, size_t base, size_t* error_offset) {
    (void)document;
    (void)parent;
    (void)data;
    (void)depth;
    (void)base;
    (void)error_offset;
    return size ? TLV_ERR_UNSUPPORTED : TLV_OK;
}
#endif

static tlv_result_t build_node(tlv_document_t* document, tlv_node_t* parent, tlv_tag_t tag,
                               const uint8_t* value, size_t length, size_t depth, size_t value_base,
                               size_t element_offset, size_t* error_offset, tlv_node_t** created) {
    tlv_node_t* node;
    int constructed =
        document->options.format->is_constructed &&
        document->options.format->is_constructed(document->options.format->context, &tag);
    tlv_result_t rc = document_create_node(document, parent, tag, value, length, constructed, depth,
                                           element_offset, error_offset, &node);
    if (rc != TLV_OK) return rc;
    if (node->constructed && length) {
        if (depth == document->options.max_depth) {
            document_set_offset(error_offset, value_base);
            rc = TLV_ERR_LIMIT;
        } else {
            rc = document_parse_list(document, node, value, length, depth + 1, value_base,
                                     error_offset);
        }
    }
    if (rc != TLV_OK) {
        node_unlink(node);
        document->count -= subtree_size(node);
        free_subtree(node);
        return rc;
    }
    if (created) *created = node;
    return TLV_OK;
}

/* ---- Lifecycle ------------------------------------------------------------------------- */

static int format_usable(const tlv_format_t* format) {
    return format != NULL;
}

tlv_result_t tlv_document_options_init(tlv_document_options_t* options,
                                       const tlv_format_t* format) {
    if (!options || !format_usable(format)) return TLV_ERR_NULL_ARG;
    options->format = format;
    options->max_depth = TLV_TREE_DEFAULT_DEPTH;
    options->max_elements = TLV_DOCUMENT_DEFAULT_MAX_ELEMENTS;
    options->allocator = NULL;
    options->retain_source_locations = 0;
    return TLV_OK;
}

tlv_result_t tlv_document_create(const tlv_document_options_t* options, tlv_document_t** document) {
    tlv_allocator_t allocator;
    tlv_document_t* created;
    if (!document) return TLV_ERR_NULL_ARG;
    *document = NULL;
    if (!options || !format_usable(options->format)) return TLV_ERR_NULL_ARG;
    if (options->allocator) {
        if (!options->allocator->allocate || !options->allocator->release) return TLV_ERR_NULL_ARG;
        allocator = *options->allocator;
    } else {
        allocator.context = NULL;
        allocator.allocate = default_allocate;
        allocator.release = default_release;
    }
    created = (tlv_document_t*)allocator.allocate(allocator.context, sizeof *created);
    if (!created) return TLV_ERR_OUT_OF_MEMORY;
    memset(created, 0, sizeof *created);
    created->options = *options;
    created->options.allocator = NULL;
    created->allocator = allocator;
    *document = created;
    return TLV_OK;
}

void tlv_document_free(tlv_document_t* document) {
    if (!document) return;
    if (document->query_callbacks) {
        document->query_pending = 2;
        return;
    }
    discard_children(document, NULL);
    document_memory_release(document, document);
}

size_t tlv_document_count(const tlv_document_t* document) {
    return document ? document->count : 0;
}

/* ---- Navigation ------------------------------------------------------------------------ */

tlv_node_t* tlv_document_first(const tlv_document_t* document) {
    return document ? document->first : NULL;
}

tlv_node_t* tlv_node_first_child(const tlv_node_t* node) {
    return node ? node->first : NULL;
}

tlv_node_t* tlv_node_next(const tlv_node_t* node) {
    return node ? node->next : NULL;
}

tlv_node_t* tlv_node_parent(const tlv_node_t* node) {
    return node ? node->parent : NULL;
}

static tlv_node_t* find_in_siblings(tlv_node_t* node, tlv_tag_t tag) {
    for (; node; node = node->next)
        if (tlv_tag_equal(document_node_tag(node), tag)) return node;
    return NULL;
}

static int tag_valid(tlv_tag_t tag) {
    return tag.data || !tag.size;
}

tlv_node_t* tlv_document_find(const tlv_document_t* document, const tlv_node_t* parent,
                              tlv_tag_t tag) {
    if (!tag_valid(tag)) return NULL;
    if (parent) return find_in_siblings(parent->first, tag);
    return document ? find_in_siblings(document->first, tag) : NULL;
}

tlv_node_t* tlv_node_next_same_tag(const tlv_node_t* node) {
    return node ? find_in_siblings(node->next, document_node_tag(node)) : NULL;
}

/* ---- Reading a node -------------------------------------------------------------------- */

tlv_tag_t tlv_node_tag(const tlv_node_t* node) {
    return node ? document_node_tag(node) : tlv_tag(NULL, 0);
}

int tlv_node_is_constructed(const tlv_node_t* node) {
    return node && node->constructed;
}

const uint8_t* tlv_node_value_data(const tlv_node_t* node) {
    return node ? node->value : NULL;
}

size_t tlv_node_value_size(const tlv_node_t* node) {
    return node ? node->value_size : 0;
}

/* ---- Modification ---------------------------------------------------------------------- */

tlv_result_t tlv_node_set_value(tlv_node_t* node, const uint8_t* value, size_t length) {
    tlv_document_t* document;
    tlv_node_t holder;
    size_t old_count;
    tlv_result_t rc;
    if (!node || (!value && length)) return TLV_ERR_NULL_ARG;
    document = node->document;
    if (document->query_callbacks) return TLV_ERR_INVALID_STATE;
    if (!node->constructed) {
        uint8_t* copy = copy_bytes(document, value, length);
        if (length && !copy) return TLV_ERR_OUT_OF_MEMORY;
        document_memory_release(document, node->value);
        node->value = copy;
        node->value_size = length;
        invalidate_locations(node);
        ++document->revision;
        return TLV_OK;
    }
    /* Parse first into a detached holder, so a failure leaves the old children in place. The
     * old children stop counting for the limit while the replacement is built. */
    memset(&holder, 0, sizeof holder);
    holder.document = document;
    old_count = subtree_size(node) - 1;
    document->count -= old_count;
    rc = document_parse_list(document, &holder, value, length, node_depth(node) + 1, 0, NULL);
    if (rc != TLV_OK) {
        discard_children(document, &holder);
        document->count += old_count;
        return rc;
    }
    free_children(node);
    node->first = holder.first;
    node->last = holder.last;
    {
        tlv_node_t* child;
        for (child = node->first; child; child = child->next) child->parent = node;
    }
    invalidate_locations(node);
    /* Only published descendants count. Empty replacements cannot consume epochs;
     * each increment retires at least one never-reused identity, so it cannot wrap. */
    if (old_count) ++document->retire_epoch;
    ++document->revision;
    return TLV_OK;
}

tlv_result_t tlv_document_insert(tlv_document_t* document, tlv_node_t* parent,
                                 const tlv_node_t* before, tlv_tag_t tag, const uint8_t* value,
                                 size_t length, tlv_node_t** node) {
    tlv_node_t holder;
    tlv_node_t* created = NULL;
    tlv_encoding_t probe_size;
    tlv_result_t rc;
    if (!document || (!value && length) || !tag_valid(tag)) return TLV_ERR_NULL_ARG;
    if (document->query_callbacks) return TLV_ERR_INVALID_STATE;
    if (parent && (parent->document != document || !parent->constructed))
        return TLV_ERR_INVALID_ARG;
    if (before && (before->document != document || before->parent != parent))
        return TLV_ERR_INVALID_ARG;
    /* Let the writer format reject a tag it could not write. */
    if (tlv_format_can_write(document->options.format)) {
        tlv_element_t probe = {tag, {NULL, 0}};
        rc = tlv_format_measure(document->options.format, &probe, &probe_size, NULL);
        if (rc == TLV_OK) rc = tlv_size_validate_native(probe_size.total);
        if (rc != TLV_OK) return rc;
    }
    memset(&holder, 0, sizeof holder);
    holder.document = document;
    rc = build_node(document, &holder, tag, value, length, parent ? node_depth(parent) + 1 : 0, 0,
                    0, NULL, &created);
    if (rc != TLV_OK) return rc;
    node_unlink(created);
    node_link(document, parent, (tlv_node_t*)before, created);
    invalidate_locations(parent);
    ++document->revision;
    if (node) *node = created;
    return TLV_OK;
}

void tlv_node_erase(tlv_node_t* node) {
    tlv_document_t* document;
    if (!node) return;
    document = node->document;
    if (document->query_callbacks) {
        node->pending_erase = 1;
        if (!document->query_pending) document->query_pending = 1;
        return;
    }
    invalidate_locations(node->parent);
    node_unlink(node);
    document->count -= subtree_size(node);
    free_subtree(node);
    ++document->retire_epoch;
    ++document->revision;
}

const tlv_format_t* document_format(const tlv_document_t* document) {
    return document ? document->options.format : NULL;
}
int document_contains(const tlv_document_t* document, const tlv_node_t* node) {
    /* Internal context validation accepts live nodes, not possibly stale handles. */
    return document && node && node->document == document;
}
uint64_t tlv_document_node_identity(const tlv_document_t* document, const tlv_node_t* wanted) {
    if (!document || !wanted) return 0;
    for (const tlv_node_t* node = document->first; node;) {
        if (node == wanted) return node->identity;
        if (node->first)
            node = node->first;
        else {
            while (node->parent && !node->next) node = node->parent;
            node = node->next;
        }
    }
    return 0;
}
uint64_t tlv_node_identity(const tlv_node_t* node) {
    return node ? node->identity : 0;
}
uint64_t tlv_document_revision(const tlv_document_t* document) {
    return document ? document->revision : 0;
}
uint64_t tlv_document_retire_epoch(const tlv_document_t* document) {
    return document ? document->retire_epoch : 0;
}
int document_query_callback(tlv_document_t* document, int active) {
    if (active) {
        ++document->query_callbacks;
        return 0;
    }
    assert(document->query_callbacks);
    if (--document->query_callbacks) return 0;
    int pending = document->query_pending;
    document->query_pending = 0;
    if (pending == 2) {
        tlv_document_free(document);
    } else if (pending == 1) {
        for (tlv_node_t* node = document->first; node;) {
            if (!node->pending_erase && node->first) {
                node = node->first;
                continue;
            }
            tlv_node_t* next = node;
            while (next->parent && !next->next) next = next->parent;
            next = next->next;
            if (node->pending_erase) tlv_node_erase(node);
            node = next;
        }
    }
    return pending;
}

#if OPENTLV_QUERY && OPENTLV_READER && OPENTLV_WRITER
tlv_result_t document_edit_targets(tlv_document_t* document, tlv_node_t** targets, size_t count,
                                   tlv_document_query_edit_kind_t kind, tlv_tag_t tag,
                                   const uint8_t* value, size_t size, size_t* applied) {
    if (document->query_callbacks) return TLV_ERR_INVALID_STATE;
    if (!count) return TLV_OK;
#ifndef NDEBUG
    /* Private input comes directly from the unique preorder Query cursor. */
    size_t ordered = 0;
    for (tlv_node_t* node = document->first; node;) {
        if (ordered < count && node == targets[ordered]) ++ordered;
        if (node->first)
            node = node->first;
        else {
            while (node->parent && !node->next) node = node->parent;
            node = node->next;
        }
    }
    assert(ordered == count);
#endif
    /* Resolve overlap against the initial topology before freeing a single node. */
    if (kind != TLV_DOCUMENT_QUERY_INSERT_AFTER) {
        tlv_node_t* covering = NULL;
        for (size_t i = 0; i < count; ++i) {
            int covered = 0;
            for (tlv_node_t* parent = targets[i]->parent; parent; parent = parent->parent) {
                if (parent == covering) {
                    covered = 1;
                    break;
                }
            }
            if (covered)
                targets[i] = NULL;
            else
                covering = targets[i];
        }
    }
    /* Preflight Format framing, Value syntax and every target's depth/count
     * limits before changing the tree. Primitive Values remain opaque bytes. */
    size_t added = 0, relative_depth = 0;
    int constructed = 0;
    if (kind == TLV_DOCUMENT_QUERY_INSERT_AFTER) {
        size_t encoded;
        if (!tag_valid(tag)) return TLV_ERR_NULL_ARG;
        tlv_result_t check = tlv_encoded_size(tag, size, document->options.format, &encoded);
        if (check != TLV_OK) return check;
        constructed =
            document->options.format->is_constructed &&
            document->options.format->is_constructed(document->options.format->context, &tag);
    } else if (kind == TLV_DOCUMENT_QUERY_REPLACE) {
        for (size_t i = 0; i < count; ++i)
            if (targets[i] && targets[i]->constructed) constructed = 1;
    }
    if (constructed && size) {
        size_t capacity = document->options.max_depth;
        if (capacity > size) capacity = size;
        if (capacity > SIZE_MAX / sizeof(tlv_tree_frame_t)) return TLV_ERR_OVERFLOW;
        tlv_tree_frame_t* frames =
            capacity ? document_memory_allocate(document, capacity * sizeof *frames) : NULL;
        if (capacity && !frames) return TLV_ERR_OUT_OF_MEMORY;
        tlv_tree_reader_t reader;
        tlv_result_t check =
            tlv_tree_reader_init(&reader, value, size, document->options.format, frames, capacity,
                                 document->options.max_depth, document->options.max_elements);
        while (check == TLV_OK) {
            tlv_tree_event_t event;
            check = tlv_tree_reader_next_event(&reader, &event);
            if (check == TLV_OK && event.kind != TLV_TREE_END) {
                ++added;
                if (event.depth > relative_depth) relative_depth = event.depth;
            }
        }
        document_memory_release(document, frames);
        if (check != TLV_ERR_END_OF_BUFFER) return check;
    }
    size_t projected = document->count;
    for (size_t i = 0; i < count; ++i) {
        tlv_node_t* target = targets[i];
        if (!target) continue;
        if (kind == TLV_DOCUMENT_QUERY_REMOVE) continue;
        if (kind == TLV_DOCUMENT_QUERY_REPLACE && !target->constructed) continue;
        size_t depth = node_depth(target);
        if (added && (depth >= document->options.max_depth ||
                      relative_depth > document->options.max_depth - depth - 1))
            return TLV_ERR_LIMIT;
        if (kind == TLV_DOCUMENT_QUERY_REPLACE)
            projected -= subtree_size(target) - 1;
        else {
            if (projected == document->options.max_elements) return TLV_ERR_LIMIT;
            ++projected;
        }
        if (added > document->options.max_elements - projected) return TLV_ERR_LIMIT;
        projected += added;
    }
    uint8_t* copy = NULL;
    if (kind != TLV_DOCUMENT_QUERY_REMOVE && size) {
        copy = copy_bytes(document, value, size);
        if (!copy) return TLV_ERR_OUT_OF_MEMORY;
    }
    tlv_result_t rc = TLV_OK;
    for (size_t i = 0; i < count; ++i) {
        tlv_node_t* target = targets[i];
        if (!target) continue;
        if (kind == TLV_DOCUMENT_QUERY_REMOVE)
            tlv_node_erase(target);
        else if (kind == TLV_DOCUMENT_QUERY_REPLACE)
            rc = tlv_node_set_value(target, copy, size);
        else
            rc = tlv_document_insert(document, target->parent, target->next, tag, copy, size, NULL);
        if (rc != TLV_OK) break;
        ++*applied;
    }
    document_memory_release(document, copy);
    return rc;
}
#endif
