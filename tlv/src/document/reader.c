// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "document_internal.h"
#include "tlv/size.h"
#include <string.h>

#include "tlv/reader/tree.h"
struct tlv_document_builder {
    tlv_document_t* document;
    tlv_allocator_t allocator;
    tlv_tree_reader_t* reader;
    tlv_node_t* container;
    int subtree_done;
    size_t source_depth;
    size_t target_depth;
    size_t base;
    int subtree;
    int retain_source_locations;
};

static tlv_result_t append_item(tlv_document_builder_t* builder, const tlv_tree_item_t* item,
                                size_t* error_offset) {
    tlv_node_t* created;
    size_t depth, length;
    tlv_result_t rc;
    if (item->depth < builder->source_depth) return TLV_ERR_INVALID_ARG;
    depth = item->depth - builder->source_depth;
    if (depth > SIZE_MAX - builder->target_depth) return TLV_ERR_LIMIT;
    rc = tlv_size_to_native(item->element.value.size, &length);
    if (rc == TLV_OK)
        rc = document_create_node(builder->document, builder->container, item->element.tag,
                                  item->element.value.data, length, item->constructed,
                                  builder->target_depth + depth, builder->base + item->offset,
                                  error_offset, &created);
    if (rc != TLV_OK) document_set_offset(error_offset, builder->base + item->offset);
    if (rc == TLV_OK && builder->retain_source_locations && item->source.data) {
        tlv_document_source_location_t* location = document_node_location(created);
        location->offset = item->offset;
        location->has_offset = 1;
        if (item->source.header.present && item->source.header.offset <= item->source.size &&
            item->source.header.size <= item->source.size - item->source.header.offset) {
            location->header_size = item->source.header.size;
            location->has_header_size = 1;
        }
    }
    if (rc == TLV_OK && item->constructed) builder->container = created;
    return rc;
}

/* Shared by complete parsing, mutation and the resumable public builder. */
static tlv_result_t consume_tree(tlv_document_builder_t* builder, size_t* error_offset,
                                 tlv_reader_diagnostic_t* diagnostic) {
    tlv_tree_reader_t* reader = builder->reader;
    while (builder->subtree ? !builder->subtree_done : !tlv_tree_reader_at_end(reader)) {
        tlv_tree_event_t event;
        tlv_result_t rc = tlv_tree_reader_next_event_diag(reader, &event, diagnostic);
        if (rc != TLV_OK) {
            document_set_offset(error_offset, builder->base + tlv_tree_reader_offset(reader));
            return rc;
        }
        if (event.kind == TLV_TREE_END) {
            if (event.skipped || !builder->container) return TLV_ERR_INVALID_ARG;
            builder->container = builder->container->parent;
            if (builder->subtree && event.depth == builder->source_depth) builder->subtree_done = 1;
        } else {
            tlv_tree_item_t item = {event.element, event.source, event.depth, event.offset,
                                    event.kind == TLV_TREE_BEGIN};
            rc = append_item(builder, &item, error_offset);
            if (rc != TLV_OK) return rc;
        }
    }
    return TLV_OK;
}

tlv_result_t document_parse_list(tlv_document_t* document, tlv_node_t* parent, const uint8_t* data,
                                 size_t size, size_t depth, size_t base, size_t* error_offset) {
    tlv_tree_reader_t reader;
    tlv_tree_frame_t* frames = NULL;
    tlv_document_builder_t builder = {0};
    size_t capacity;
    tlv_result_t rc;
    if (size && depth > document->options.max_depth) {
        document_set_offset(error_offset, base);
        return TLV_ERR_LIMIT;
    }
    capacity = depth > document->options.max_depth ? 0 : document->options.max_depth - depth;
    /* Every nonempty encoding consumes at least one byte and one publication. */
    if (capacity > size) capacity = size;
    if (capacity > document->options.max_elements - document->count)
        capacity = document->options.max_elements - document->count;
    if (capacity > SIZE_MAX / sizeof *frames) return TLV_ERR_OUT_OF_MEMORY;
    if (capacity) {
        frames = (tlv_tree_frame_t*)document_memory_allocate(document, capacity * sizeof *frames);
        if (!frames) return TLV_ERR_OUT_OF_MEMORY;
    }
    rc = tlv_tree_reader_init(&reader, data, size, document->options.format, frames, capacity,
                              capacity, document->options.max_elements - document->count);
    builder.document = document;
    builder.reader = &reader;
    builder.container = parent;
    builder.target_depth = depth;
    builder.base = base;
    /* Only initial top-level parsing imports provenance. Mutation buffers have
     * no coordinates in the original Document input. */
    builder.retain_source_locations = !parent && document->options.retain_source_locations;
    if (rc == TLV_OK) rc = consume_tree(&builder, error_offset, NULL);
    document_memory_release(document, frames);
    return rc;
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
    rc = document_parse_list(created, NULL, data, size, 0, 0, error_offset);
    if (rc != TLV_OK) {
        tlv_document_free(created);
        return rc;
    }
    *document = created;
    return TLV_OK;
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
    created = (tlv_document_builder_t*)document_memory_allocate(document, sizeof *created);
    if (!created) {
        tlv_document_free(document);
        return TLV_ERR_OUT_OF_MEMORY;
    }
    memset(created, 0, sizeof *created);
    created->document = document;
    created->allocator = document->allocator;
    created->reader = reader;
    created->retain_source_locations = options->retain_source_locations;
    if (root) {
        created->subtree = 1;
        created->subtree_done = !root->constructed || !root->element.value.size;
        created->source_depth = root->depth;
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
