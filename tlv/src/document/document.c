#include "tlv/document/document.h"
#include "tlv/size.h"
#include "tlv/reader/tree.h"
#include "tlv/writer/tree.h"
#include <stdlib.h>
#include <string.h>

/* The tag bytes are stored directly after this structure in the same allocation. */
struct tlv_node {
    tlv_document_t* document;
    tlv_node_t* parent;
    tlv_node_t* prev;
    tlv_node_t* next;
    tlv_node_t* first;
    tlv_node_t* last;
    uint8_t* value;
    size_t value_size;
    size_t tag_size;
    int constructed;
};

struct tlv_document {
    tlv_document_options_t options;
    tlv_allocator_t allocator;
    tlv_node_t* first;
    tlv_node_t* last;
    size_t count;
};

struct tlv_document_builder {
    tlv_document_t* document;
    tlv_allocator_t allocator;
    tlv_tree_reader_t* reader;
    tlv_node_t* parent;
    tlv_node_t* previous;
    size_t previous_depth;
    size_t source_depth;
    size_t target_depth;
    size_t base;
    size_t end;
    int subtree;
};

/* ---- Memory ---------------------------------------------------------------------------- */

static void* default_allocate(void* context, size_t size) {
    (void)context;
    return malloc(size);
}

static void default_release(void* context, void* memory) {
    (void)context;
    free(memory);
}

static void* memory_allocate(const tlv_document_t* document, size_t size) {
    return document->allocator.allocate(document->allocator.context, size);
}

static void memory_release(const tlv_document_t* document, void* memory) {
    if (memory) document->allocator.release(document->allocator.context, memory);
}

/* ---- Nodes ----------------------------------------------------------------------------- */

static const uint8_t* node_tag_data(const tlv_node_t* node) {
    return (const uint8_t*)(node + 1);
}

static tlv_tag_t node_tag(const tlv_node_t* node) {
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
            memory_release(node->document, node->value);
            memory_release(node->document, node);
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
    copy = (uint8_t*)memory_allocate(document, size);
    if (copy) memcpy(copy, data, size);
    return copy;
}

/* ---- Parsing --------------------------------------------------------------------------- */

static void set_offset(size_t* out, size_t offset) {
    if (out) *out = offset;
}

static tlv_result_t parse_list(tlv_document_t* document, tlv_node_t* parent, const uint8_t* data,
                               size_t size, size_t depth, size_t base, size_t* error_offset);

/*
 * Creates one owned node; constructed children are supplied by the Tree Reader consumer.
 */
static tlv_result_t create_node(tlv_document_t* document, tlv_node_t* parent, tlv_tag_t tag,
                                const uint8_t* value, size_t length, int constructed, size_t depth,
                                size_t element_offset, size_t* error_offset, tlv_node_t** created) {
    tlv_node_t* node;
    if (depth > document->options.max_depth || document->count >= document->options.max_elements) {
        set_offset(error_offset, element_offset);
        return TLV_ERR_LIMIT;
    }
    if (tag.size > SIZE_MAX - sizeof *node) return TLV_ERR_OUT_OF_MEMORY;
    node = (tlv_node_t*)memory_allocate(document, sizeof *node + tag.size);
    if (!node) return TLV_ERR_OUT_OF_MEMORY;
    memset(node, 0, sizeof *node);
    node->document = document;
    node->tag_size = tag.size;
    if (tag.size) memcpy(node + 1, tag.data, tag.size);
    node->constructed = constructed;
    if (!node->constructed && length) {
        node->value = copy_bytes(document, value, length);
        if (!node->value) {
            memory_release(document, node);
            return TLV_ERR_OUT_OF_MEMORY;
        }
        node->value_size = length;
    }
    node_link(document, parent, NULL, node);
    ++document->count;
    *created = node;
    return TLV_OK;
}

static tlv_result_t append_item(tlv_document_builder_t* builder, const tlv_tree_item_t* item,
                                size_t* error_offset) {
    tlv_node_t* container = builder->parent;
    size_t depth, length;
    tlv_result_t rc;
    if (item->depth < builder->source_depth) return TLV_ERR_INVALID_ARG;
    depth = item->depth - builder->source_depth;
    if (depth > SIZE_MAX - builder->target_depth) return TLV_ERR_LIMIT;
    if (builder->previous) {
        if (depth > builder->previous_depth) {
            container = builder->previous;
        } else {
            while (builder->previous_depth > depth) {
                builder->previous = builder->previous->parent;
                --builder->previous_depth;
            }
            container = builder->previous->parent;
        }
    }
    rc = tlv_size_to_native(item->element.value.size, &length);
    if (rc == TLV_OK)
        rc = create_node(builder->document, container, item->element.tag, item->element.value.data,
                         length, item->constructed, builder->target_depth + depth,
                         builder->base + item->offset, error_offset, &builder->previous);
    if (rc != TLV_OK) set_offset(error_offset, builder->base + item->offset);
    builder->previous_depth = depth;
    return rc;
}

/* Shared by complete parsing, mutation and the resumable public builder. */
static tlv_result_t consume_tree(tlv_document_builder_t* builder, size_t* error_offset,
                                 tlv_reader_diagnostic_t* diagnostic) {
    tlv_tree_reader_t* reader = builder->reader;
    while (builder->subtree ? tlv_tree_reader_offset(reader) < builder->end
                            : !tlv_tree_reader_at_end(reader)) {
        tlv_tree_item_t item;
        tlv_result_t rc = tlv_tree_reader_next_diag(reader, &item, diagnostic);
        if (rc != TLV_OK) {
            set_offset(error_offset, builder->base + tlv_tree_reader_offset(reader));
            return rc;
        }
        rc = append_item(builder, &item, error_offset);
        if (rc != TLV_OK) return rc;
    }
    return TLV_OK;
}

static tlv_result_t parse_list(tlv_document_t* document, tlv_node_t* parent, const uint8_t* data,
                               size_t size, size_t depth, size_t base, size_t* error_offset) {
    tlv_tree_reader_t reader;
    tlv_tree_frame_t* frames = NULL;
    tlv_document_builder_t builder = {0};
    size_t capacity;
    tlv_result_t rc;
    if (size && depth > document->options.max_depth) {
        set_offset(error_offset, base);
        return TLV_ERR_LIMIT;
    }
    capacity = depth > document->options.max_depth ? 0 : document->options.max_depth - depth;
    /* Every nonempty encoding consumes at least one byte and one publication. */
    if (capacity > size) capacity = size;
    if (capacity > document->options.max_elements - document->count)
        capacity = document->options.max_elements - document->count;
    if (capacity > SIZE_MAX / sizeof *frames) return TLV_ERR_OUT_OF_MEMORY;
    if (capacity) {
        frames = (tlv_tree_frame_t*)memory_allocate(document, capacity * sizeof *frames);
        if (!frames) return TLV_ERR_OUT_OF_MEMORY;
    }
    rc = tlv_tree_reader_init(&reader, data, size, document->options.format, frames, capacity,
                              capacity, document->options.max_elements - document->count);
    builder.document = document;
    builder.reader = &reader;
    builder.parent = parent;
    builder.target_depth = depth;
    builder.base = base;
    if (rc == TLV_OK) rc = consume_tree(&builder, error_offset, NULL);
    memory_release(document, frames);
    return rc;
}

static tlv_result_t build_node(tlv_document_t* document, tlv_node_t* parent, tlv_tag_t tag,
                               const uint8_t* value, size_t length, size_t depth, size_t value_base,
                               size_t element_offset, size_t* error_offset, tlv_node_t** created) {
    tlv_node_t* node;
    int constructed =
        document->options.format->is_constructed &&
        document->options.format->is_constructed(document->options.format->context, &tag);
    tlv_result_t rc = create_node(document, parent, tag, value, length, constructed, depth,
                                  element_offset, error_offset, &node);
    if (rc != TLV_OK) return rc;
    if (node->constructed && length) {
        if (depth == document->options.max_depth) {
            set_offset(error_offset, value_base);
            rc = TLV_ERR_LIMIT;
        } else {
            rc = parse_list(document, node, value, length, depth + 1, value_base, error_offset);
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
    return tlv_format_can_read(format) && tlv_format_can_write(format);
}

tlv_result_t tlv_document_options_init(tlv_document_options_t* options,
                                       const tlv_format_t* format) {
    if (!options || !format_usable(format)) return TLV_ERR_NULL_ARG;
    options->format = format;
    options->max_depth = TLV_TREE_DEFAULT_DEPTH;
    options->max_elements = TLV_DOCUMENT_DEFAULT_MAX_ELEMENTS;
    options->allocator = NULL;
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

tlv_result_t tlv_document_parse(const uint8_t* data, size_t size,
                                const tlv_document_options_t* options, tlv_document_t** document,
                                size_t* error_offset) {
    tlv_document_t* created;
    tlv_result_t rc;
    if (!document) return TLV_ERR_NULL_ARG;
    *document = NULL;
    if (!data && size) return TLV_ERR_NULL_ARG;
    rc = tlv_document_create(options, &created);
    if (rc != TLV_OK) return rc;
    rc = parse_list(created, NULL, data, size, 0, 0, error_offset);
    if (rc != TLV_OK) {
        tlv_document_free(created);
        return rc;
    }
    *document = created;
    return TLV_OK;
}

void tlv_document_free(tlv_document_t* document) {
    if (!document) return;
    discard_children(document, NULL);
    memory_release(document, document);
}

tlv_result_t tlv_document_builder_create(const tlv_document_options_t* options,
                                         tlv_tree_reader_t* reader, const tlv_tree_item_t* root,
                                         tlv_document_builder_t** builder) {
    tlv_document_t* document;
    tlv_document_builder_t* created;
    tlv_result_t rc;
    if (!builder) return TLV_ERR_NULL_ARG;
    *builder = NULL;
    if (!options || !reader) return TLV_ERR_NULL_ARG;
    if (options->format != reader->input.format) return TLV_ERR_INVALID_ARG;
    if ((!root && reader->count) ||
        (root && (root->source.format != options->format || !root->source.size ||
                  root->offset > SIZE_MAX - root->source.size)))
        return TLV_ERR_INVALID_ARG;
    rc = tlv_document_create(options, &document);
    if (rc != TLV_OK) return rc;
    created = (tlv_document_builder_t*)memory_allocate(document, sizeof *created);
    if (!created) {
        tlv_document_free(document);
        return TLV_ERR_OUT_OF_MEMORY;
    }
    memset(created, 0, sizeof *created);
    created->document = document;
    created->allocator = document->allocator;
    created->reader = reader;
    if (root) {
        created->subtree = 1;
        created->source_depth = root->depth;
        created->end = root->offset + root->source.size;
        rc = append_item(created, root, NULL);
        if (rc != TLV_OK) {
            tlv_document_builder_free(created);
            return rc;
        }
    }
    *builder = created;
    return TLV_OK;
}

tlv_result_t tlv_document_builder_consume(tlv_document_builder_t* builder,
                                          tlv_document_t** document, size_t* error_offset,
                                          tlv_reader_diagnostic_t* diagnostic) {
    tlv_result_t rc;
    if (!document) return TLV_ERR_NULL_ARG;
    *document = NULL;
    if (!builder) return TLV_ERR_NULL_ARG;
    if (!builder->document) return TLV_ERR_INVALID_ARG;
    rc = consume_tree(builder, error_offset, diagnostic);
    if (rc == TLV_NEED_MORE_DATA) return rc;
    if (rc == TLV_OK)
        *document = builder->document;
    else
        tlv_document_free(builder->document);
    builder->document = NULL;
    return rc;
}

void tlv_document_builder_free(tlv_document_builder_t* builder) {
    if (!builder) return;
    tlv_document_free(builder->document);
    builder->allocator.release(builder->allocator.context, builder);
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
        if (tlv_tag_equal(node_tag(node), tag)) return node;
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
    return node ? find_in_siblings(node->next, node_tag(node)) : NULL;
}

tlv_node_t* tlv_document_find_path(const tlv_document_t* document, const tlv_query_t* query) {
    tlv_query_matcher_t matcher;
    tlv_node_t* node;
    size_t depth = 0;
    if (!document || tlv_query_matcher_init(&matcher, query) != TLV_OK) return NULL;
    node = document->first;
    while (node) {
        tlv_tag_t tag = node_tag(node);
        if (tlv_query_matcher_visit(&matcher, &tag, depth)) return node;
        if (node->first) {
            node = node->first;
            ++depth;
        } else {
            while (node->parent && !node->next) {
                node = node->parent;
                --depth;
            }
            node = node->next;
        }
    }
    return NULL;
}

/* ---- Reading a node -------------------------------------------------------------------- */

tlv_tag_t tlv_node_tag(const tlv_node_t* node) {
    return node ? node_tag(node) : tlv_tag(NULL, 0);
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
    if (!node->constructed) {
        uint8_t* copy = copy_bytes(document, value, length);
        if (length && !copy) return TLV_ERR_OUT_OF_MEMORY;
        memory_release(document, node->value);
        node->value = copy;
        node->value_size = length;
        return TLV_OK;
    }
    /* Parse first into a detached holder, so a failure leaves the old children in place. The
     * old children stop counting for the limit while the replacement is built. */
    memset(&holder, 0, sizeof holder);
    holder.document = document;
    old_count = subtree_size(node) - 1;
    document->count -= old_count;
    rc = parse_list(document, &holder, value, length, node_depth(node) + 1, 0, NULL);
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
    return TLV_OK;
}

tlv_result_t tlv_document_insert(tlv_document_t* document, tlv_node_t* parent,
                                 const tlv_node_t* before, tlv_tag_t tag, const uint8_t* value,
                                 size_t length, tlv_node_t** node) {
    tlv_node_t holder;
    tlv_node_t* created = NULL;
    size_t probe_size;
    tlv_result_t rc;
    if (!document || (!value && length) || !tag_valid(tag)) return TLV_ERR_NULL_ARG;
    if (parent && (parent->document != document || !parent->constructed))
        return TLV_ERR_INVALID_ARG;
    if (before && (before->document != document || before->parent != parent))
        return TLV_ERR_INVALID_ARG;
    /* Let the writer format reject a tag it could not write. */
    rc = tlv_encoded_size(tag, 0, document->options.format, &probe_size);
    if (rc != TLV_OK) return rc;
    memset(&holder, 0, sizeof holder);
    holder.document = document;
    rc = build_node(document, &holder, tag, value, length, parent ? node_depth(parent) + 1 : 0, 0,
                    0, NULL, &created);
    if (rc != TLV_OK) return rc;
    node_unlink(created);
    node_link(document, parent, (tlv_node_t*)before, created);
    if (node) *node = created;
    return TLV_OK;
}

void tlv_node_erase(tlv_node_t* node) {
    tlv_document_t* document;
    if (!node) return;
    document = node->document;
    node_unlink(node);
    document->count -= subtree_size(node);
    free_subtree(node);
}

/* ---- Encoding -------------------------------------------------------------------------- */

/* Document supplies topology and semantic Values; Tree Writer owns scope closure,
 * measurement and wire emission. No byte counts are attached to Document nodes. */
typedef struct document_source {
    const tlv_node_t* next;
    size_t depth;
    int single;
} document_source_t;

static tlv_result_t document_next(void* context, tlv_element_t* element, size_t* depth,
                                  int* constructed) {
    document_source_t* source = (document_source_t*)context;
    const tlv_node_t* node = source->next;
    if (!node) return TLV_ERR_END_OF_BUFFER;
    *element = (tlv_element_t){node_tag(node), {node->value, node->value_size}};
    *depth = source->depth;
    *constructed = node->constructed;
    if (node->first) {
        source->next = node->first;
        ++source->depth;
    } else {
        while (source->depth && !node->next) {
            node = node->parent;
            --source->depth;
        }
        source->next = !source->depth && source->single ? NULL : node->next;
    }
    return TLV_OK;
}

static tlv_result_t grow_workspace(const tlv_document_t* document, uint8_t** data, size_t* capacity,
                                   size_t required) {
    size_t grown;
    uint8_t* replacement;
    if (required <= *capacity) return TLV_OK;
    grown = *capacity <= SIZE_MAX / 2 ? *capacity * 2 : required;
    if (grown < 256) grown = 256;
    if (grown < required) grown = required;
    replacement = (uint8_t*)memory_allocate(document, grown);
    if (!replacement) return TLV_ERR_OUT_OF_MEMORY;
    memory_release(document, *data);
    *data = replacement;
    *capacity = grown;
    return TLV_OK;
}

static void release_workspace(const tlv_document_t* document,
                              tlv_tree_writer_workspace_t* workspace) {
    memory_release(document, workspace->frames);
    memory_release(document, workspace->data);
    memory_release(document, workspace->scratch);
}

static tlv_result_t prepare_encoding(const tlv_document_t* document, const tlv_node_t* first,
                                     int single, const tlv_format_t* format,
                                     tlv_tree_writer_workspace_t* workspace, size_t* size) {
    document_source_t source = {first, 0, single};
    tlv_element_t element;
    size_t depth;
    int constructed;
    tlv_result_t rc;
    if (!tlv_format_can_write(format)) return TLV_ERR_NULL_ARG;
    /* Size only the structural stack here, never wire representations. */
    while (document_next(&source, &element, &depth, &constructed) == TLV_OK) {
        if (constructed) {
            if (depth >= SIZE_MAX / sizeof *workspace->frames) return TLV_ERR_OUT_OF_MEMORY;
            if (depth + 1 > workspace->frame_capacity) workspace->frame_capacity = depth + 1;
        }
    }
    if (workspace->frame_capacity) {
        workspace->frames = (tlv_tree_writer_frame_t*)memory_allocate(
            document, workspace->frame_capacity * sizeof *workspace->frames);
        if (!workspace->frames) return TLV_ERR_OUT_OF_MEMORY;
    }
    for (;;) {
        source = (document_source_t){first, 0, single};
        rc = tlv_tree_writer_measure(format, document_next, &source, workspace, SIZE_MAX, SIZE_MAX,
                                     size, NULL);
        if (rc != TLV_ERR_BUFFER_TOO_SHORT ||
            (!workspace->required_data && !workspace->required_scratch))
            return rc;
        rc = grow_workspace(document, &workspace->data, &workspace->data_capacity,
                            workspace->required_data);
        if (rc != TLV_OK) return rc;
        rc = grow_workspace(document, &workspace->scratch, &workspace->scratch_capacity,
                            workspace->required_scratch);
        if (rc != TLV_OK) return rc;
    }
}

static tlv_result_t encoded_size_as(const tlv_document_t* document, const tlv_node_t* first,
                                    int single, const tlv_format_t* format, size_t* size) {
    tlv_tree_writer_workspace_t workspace = {0};
    size_t total;
    tlv_result_t rc = prepare_encoding(document, first, single, format, &workspace, &total);
    release_workspace(document, &workspace);
    if (rc == TLV_OK) *size = total;
    return rc;
}

static tlv_result_t encode_as(const tlv_document_t* document, const tlv_node_t* first, int single,
                              const tlv_format_t* format, uint8_t* data, size_t capacity,
                              size_t* written) {
    tlv_tree_writer_workspace_t workspace = {0};
    tlv_writer_t writer;
    size_t total;
    tlv_result_t rc = prepare_encoding(document, first, single, format, &workspace, &total);
    if (rc == TLV_OK && capacity < total) {
        *written = total;
        rc = TLV_ERR_BUFFER_TOO_SHORT;
    } else if (rc == TLV_OK) {
        rc = tlv_writer_init(&writer, data, capacity, format);
        if (rc == TLV_OK) rc = tlv_writer_copy_encoded(&writer, workspace.data, total);
        if (rc == TLV_OK) *written = tlv_writer_size(&writer);
    }
    release_workspace(document, &workspace);
    return rc;
}

tlv_result_t tlv_document_encoded_size_as(const tlv_document_t* document,
                                          const tlv_format_t* format, size_t* size) {
    if (!document || !size) return TLV_ERR_NULL_ARG;
    return encoded_size_as(document, document->first, 0, format, size);
}

tlv_result_t tlv_document_encoded_size(const tlv_document_t* document, size_t* size) {
    return tlv_document_encoded_size_as(document, document ? document->options.format : NULL, size);
}

tlv_result_t tlv_document_encode_as(const tlv_document_t* document, const tlv_format_t* format,
                                    uint8_t* data, size_t capacity, size_t* written) {
    if (!document || !written || (!data && capacity)) return TLV_ERR_NULL_ARG;
    return encode_as(document, document->first, 0, format, data, capacity, written);
}

tlv_result_t tlv_document_encode(const tlv_document_t* document, uint8_t* data, size_t capacity,
                                 size_t* written) {
    return tlv_document_encode_as(document, document ? document->options.format : NULL, data,
                                  capacity, written);
}

tlv_result_t tlv_node_encoded_size_as(const tlv_node_t* node, const tlv_format_t* format,
                                      size_t* size) {
    if (!node || !size) return TLV_ERR_NULL_ARG;
    return encoded_size_as(node->document, node, 1, format, size);
}

tlv_result_t tlv_node_encoded_size(const tlv_node_t* node, size_t* size) {
    return tlv_node_encoded_size_as(node, node ? node->document->options.format : NULL, size);
}

tlv_result_t tlv_node_encode_as(const tlv_node_t* node, const tlv_format_t* format, uint8_t* data,
                                size_t capacity, size_t* written) {
    if (!node || !written || (!data && capacity)) return TLV_ERR_NULL_ARG;
    return encode_as(node->document, node, 1, format, data, capacity, written);
}

tlv_result_t tlv_node_encode(const tlv_node_t* node, uint8_t* data, size_t capacity,
                             size_t* written) {
    return tlv_node_encode_as(node, node ? node->document->options.format : NULL, data, capacity,
                              written);
}
