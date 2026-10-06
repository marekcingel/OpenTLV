// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "document_internal.h"
#include "tlv/size.h"
#include <string.h>

#include "tlv/writer/tree.h"
/* ---- Encoding -------------------------------------------------------------------------- */

/* Document supplies topology and semantic Values; Tree Writer owns scope closure,
 * measurement and wire emission. No byte counts are attached to Document nodes. */
typedef struct document_source {
    const tlv_node_t* next;
    size_t depth;
    int single;
    int closing;
} document_source_t;

/* Materialized topology supplies explicit opens and closes, without byte parsing. */
static tlv_result_t document_next(void* context, tlv_tree_event_t* event) {
    document_source_t* source = (document_source_t*)context;
    const tlv_node_t* node = source->next;
    if (!node) return TLV_ERR_END_OF_BUFFER;
    memset(event, 0, sizeof *event);
    event->depth = source->depth;
    if (source->closing) {
        event->kind = TLV_TREE_END;
    } else {
        event->kind = node->constructed ? TLV_TREE_BEGIN : TLV_TREE_ELEMENT;
        event->element = (tlv_element_t){document_node_tag(node), {node->value, node->value_size}};
        if (node->constructed) {
            if (node->first) {
                source->next = node->first;
                ++source->depth;
            } else {
                source->closing = 1;
            }
            return TLV_OK;
        }
    }
    source->closing = 0;
    if (!source->depth && source->single) {
        source->next = NULL;
    } else if (node->next) {
        source->next = node->next;
    } else if (source->depth) {
        source->next = node->parent;
        --source->depth;
        source->closing = 1;
    } else {
        source->next = NULL;
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
    replacement = (uint8_t*)document_memory_allocate(document, grown);
    if (!replacement) return TLV_ERR_OUT_OF_MEMORY;
    document_memory_release(document, *data);
    *data = replacement;
    *capacity = grown;
    return TLV_OK;
}

static void release_workspace(const tlv_document_t* document,
                              tlv_tree_writer_workspace_t* workspace) {
    document_memory_release(document, workspace->frames);
    document_memory_release(document, workspace->data);
    document_memory_release(document, workspace->scratch);
}

static tlv_result_t prepare_encoding(const tlv_document_t* document, const tlv_node_t* first,
                                     int single, const tlv_format_t* format,
                                     tlv_tree_writer_workspace_t* workspace, size_t* size) {
    document_source_t source = {first, 0, single, 0};
    tlv_tree_event_t event;
    tlv_result_t rc;
    if (!tlv_format_can_write(format)) return TLV_ERR_NULL_ARG;
    /* Size only the structural stack here, never wire representations. */
    while (document_next(&source, &event) == TLV_OK) {
        if (event.kind == TLV_TREE_BEGIN) {
            if (event.depth >= SIZE_MAX / sizeof *workspace->frames) return TLV_ERR_OUT_OF_MEMORY;
            if (event.depth + 1 > workspace->frame_capacity)
                workspace->frame_capacity = event.depth + 1;
        }
    }
    if (workspace->frame_capacity) {
        workspace->frames = (tlv_tree_writer_frame_t*)document_memory_allocate(
            document, workspace->frame_capacity * sizeof *workspace->frames);
        if (!workspace->frames) return TLV_ERR_OUT_OF_MEMORY;
    }
    for (;;) {
        source = (document_source_t){first, 0, single, 0};
        rc = tlv_tree_writer_measure_events(format, document_next, &source, workspace, SIZE_MAX,
                                            SIZE_MAX, size, NULL);
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
