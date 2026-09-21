#include "tlv/document/document.h"
#include "tlv/length.h"
#include "tlv/reader/reader.h"
#include "tlv/writer/writer.h"
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

/* Recursion is bounded by the document's depth limit, which is at most TLV_WALK_MAX_DEPTH. */
static size_t subtree_size(const tlv_node_t* node) {
    size_t total = 1;
    const tlv_node_t* child;
    for (child = node->first; child; child = child->next) total += subtree_size(child);
    return total;
}

static void free_children(tlv_node_t* node);

/* Frees memory only; the caller keeps the element count and the links consistent. */
static void free_subtree(tlv_node_t* node) {
    free_children(node);
    memory_release(node->document, node->value);
    memory_release(node->document, node);
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
 * Creates the element and appends it to `parent`'s children (NULL: the top level), parsing the
 * value as nested elements for a constructed tag. On failure nothing stays behind.
 */
static tlv_result_t build_node(tlv_document_t* document, tlv_node_t* parent, tlv_tag_t tag,
                               const uint8_t* value, size_t length, size_t depth, size_t value_base,
                               size_t element_offset, size_t* error_offset, tlv_node_t** created) {
    tlv_node_t* node;
    tlv_result_t rc = TLV_OK;
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
    node->constructed =
        document->options.is_constructed &&
        document->options.is_constructed(document->options.reader_format->context, &tag) != 0;
    node_link(document, parent, NULL, node);
    ++document->count;
    if (node->constructed) {
        if (length)
            rc = parse_list(document, node, value, length, depth + 1, value_base, error_offset);
    } else if (length) {
        node->value = copy_bytes(document, value, length);
        if (!node->value)
            rc = TLV_ERR_OUT_OF_MEMORY;
        else
            node->value_size = length;
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

static tlv_result_t parse_list(tlv_document_t* document, tlv_node_t* parent, const uint8_t* data,
                               size_t size, size_t depth, size_t base, size_t* error_offset) {
    tlv_reader_t reader;
    tlv_result_t rc = tlv_reader_init(&reader, data, size, document->options.reader_format);
    if (rc != TLV_OK) return rc;
    while (!tlv_reader_at_end(&reader)) {
        tlv_view_t view;
        size_t start = reader.pos, length = 0;
        rc = tlv_reader_next(&reader, &view);
        if (rc == TLV_OK) rc = tlv_length_to_size(view.value.length, &length);
        if (rc != TLV_OK) {
            set_offset(error_offset, base + start);
            return rc;
        }
        rc = build_node(document, parent, view.tag, view.value.data, length, depth,
                        length ? base + (size_t)(view.value.data - data) : 0, base + start,
                        error_offset, NULL);
        if (rc != TLV_OK) return rc;
    }
    return TLV_OK;
}

/* ---- Lifecycle ------------------------------------------------------------------------- */

static int formats_usable(const tlv_reader_format_t* reader, const tlv_writer_format_t* writer) {
    tlv_reader_t probe_reader;
    tlv_writer_t probe_writer;
    return tlv_reader_init(&probe_reader, NULL, 0, reader) == TLV_OK &&
           tlv_writer_init(&probe_writer, NULL, 0, writer) == TLV_OK;
}

tlv_result_t tlv_document_options_init(tlv_document_options_t* options,
                                       const tlv_reader_format_t* reader_format,
                                       const tlv_writer_format_t* writer_format,
                                       tlv_is_constructed_fn is_constructed) {
    if (!options || !formats_usable(reader_format, writer_format)) return TLV_ERR_NULL_ARG;
    options->reader_format = reader_format;
    options->writer_format = writer_format;
    options->is_constructed = is_constructed;
    options->max_depth = TLV_WALK_MAX_DEPTH;
    options->max_elements = TLV_DOCUMENT_DEFAULT_MAX_ELEMENTS;
    options->allocator = NULL;
    return TLV_OK;
}

tlv_result_t tlv_document_create(const tlv_document_options_t* options, tlv_document_t** document) {
    tlv_allocator_t allocator;
    tlv_document_t* created;
    if (!document) return TLV_ERR_NULL_ARG;
    *document = NULL;
    if (!options || !formats_usable(options->reader_format, options->writer_format))
        return TLV_ERR_NULL_ARG;
    if (options->max_depth > TLV_WALK_MAX_DEPTH) return TLV_ERR_LIMIT;
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

/* Recursion is bounded by TLV_QUERY_MAX_STEPS. */
static tlv_node_t* find_path(tlv_node_t* first, const tlv_query_t* query, size_t step) {
    tlv_tag_t tag = tlv_query_step(query, step);
    tlv_node_t* node;
    for (node = first; node; node = node->next) {
        if (!tlv_tag_equal(node_tag(node), tag)) continue;
        if (step + 1 == query->count) return node;
        if (node->constructed) {
            tlv_node_t* found = find_path(node->first, query, step + 1);
            if (found) return found;
        }
    }
    return NULL;
}

tlv_node_t* tlv_document_find_path(const tlv_document_t* document, const tlv_query_t* query) {
    if (!document || !query || !query->count || query->count > TLV_QUERY_MAX_STEPS) return NULL;
    return find_path(document->first, query, 0);
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
    rc = tlv_encoded_size(tag, 0, document->options.writer_format, &probe_size);
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

static tlv_result_t node_encoded_size_impl(const tlv_node_t* node, size_t* size);

static tlv_result_t list_encoded_size(const tlv_node_t* first, size_t* size) {
    size_t total = 0;
    const tlv_node_t* node;
    for (node = first; node; node = node->next) {
        size_t part;
        tlv_result_t rc = node_encoded_size_impl(node, &part);
        if (rc != TLV_OK) return rc;
        if (part > SIZE_MAX - total) return TLV_ERR_OVERFLOW;
        total += part;
    }
    *size = total;
    return TLV_OK;
}

static tlv_result_t node_value_size(const tlv_node_t* node, size_t* size) {
    if (!node->constructed) {
        *size = node->value_size;
        return TLV_OK;
    }
    return list_encoded_size(node->first, size);
}

static tlv_result_t node_encoded_size_impl(const tlv_node_t* node, size_t* size) {
    size_t value_size;
    tlv_result_t rc = node_value_size(node, &value_size);
    if (rc != TLV_OK) return rc;
    return tlv_encoded_size(node_tag(node), value_size, node->document->options.writer_format,
                            size);
}

static tlv_result_t encode_node(const tlv_node_t* node, tlv_writer_t* writer);

static tlv_result_t encode_list(const tlv_node_t* first, tlv_writer_t* writer) {
    const tlv_node_t* node;
    for (node = first; node; node = node->next) {
        tlv_result_t rc = encode_node(node, writer);
        if (rc != TLV_OK) return rc;
    }
    return TLV_OK;
}

/*
 * The header carries the value length, so a constructed value is encoded first into a
 * temporary buffer and then written with the element through the writer.
 */
static tlv_result_t encode_node(const tlv_node_t* node, tlv_writer_t* writer) {
    const tlv_document_t* document = node->document;
    tlv_writer_t inner;
    uint8_t* scratch;
    size_t value_size;
    tlv_result_t rc;
    if (!node->constructed)
        return tlv_writer_write(writer, node_tag(node), node->value, node->value_size);
    rc = list_encoded_size(node->first, &value_size);
    if (rc != TLV_OK) return rc;
    if (!value_size) return tlv_writer_write(writer, node_tag(node), NULL, 0);
    scratch = (uint8_t*)memory_allocate(document, value_size);
    if (!scratch) return TLV_ERR_OUT_OF_MEMORY;
    rc = tlv_writer_init(&inner, scratch, value_size, document->options.writer_format);
    if (rc == TLV_OK) rc = encode_list(node->first, &inner);
    if (rc == TLV_OK)
        rc = tlv_writer_write(writer, node_tag(node), scratch, tlv_writer_size(&inner));
    memory_release(document, scratch);
    return rc;
}

static tlv_result_t encode_checked(const tlv_node_t* first, const tlv_writer_format_t* format,
                                   size_t total, uint8_t* data, size_t capacity, size_t* written) {
    tlv_writer_t writer;
    tlv_result_t rc;
    if (!written || (!data && capacity)) return TLV_ERR_NULL_ARG;
    if (capacity < total) {
        *written = total;
        return TLV_ERR_BUFFER_TOO_SHORT;
    }
    rc = tlv_writer_init(&writer, data, capacity, format);
    if (rc == TLV_OK) rc = encode_list(first, &writer);
    if (rc == TLV_OK) *written = tlv_writer_size(&writer);
    return rc;
}

tlv_result_t tlv_document_encoded_size(const tlv_document_t* document, size_t* size) {
    size_t total;
    tlv_result_t rc;
    if (!document || !size) return TLV_ERR_NULL_ARG;
    rc = list_encoded_size(document->first, &total);
    if (rc == TLV_OK) *size = total;
    return rc;
}

tlv_result_t tlv_document_encode(const tlv_document_t* document, uint8_t* data, size_t capacity,
                                 size_t* written) {
    size_t total;
    tlv_result_t rc;
    if (!document || !written) return TLV_ERR_NULL_ARG;
    rc = list_encoded_size(document->first, &total);
    if (rc != TLV_OK) return rc;
    return encode_checked(document->first, document->options.writer_format, total, data, capacity,
                          written);
}

tlv_result_t tlv_node_encoded_size(const tlv_node_t* node, size_t* size) {
    size_t total;
    tlv_result_t rc;
    if (!node || !size) return TLV_ERR_NULL_ARG;
    rc = node_encoded_size_impl(node, &total);
    if (rc == TLV_OK) *size = total;
    return rc;
}

tlv_result_t tlv_node_encode(const tlv_node_t* node, uint8_t* data, size_t capacity,
                             size_t* written) {
    tlv_writer_t writer;
    size_t total;
    tlv_result_t rc;
    if (!node || !written || (!data && capacity)) return TLV_ERR_NULL_ARG;
    rc = node_encoded_size_impl(node, &total);
    if (rc != TLV_OK) return rc;
    if (capacity < total) {
        *written = total;
        return TLV_ERR_BUFFER_TOO_SHORT;
    }
    rc = tlv_writer_init(&writer, data, capacity, node->document->options.writer_format);
    if (rc == TLV_OK) rc = encode_node(node, &writer);
    if (rc == TLV_OK) *written = tlv_writer_size(&writer);
    return rc;
}
