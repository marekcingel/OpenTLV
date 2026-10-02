// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv/reader/tree.h"

/* END is structural: no borrowed parent needs to survive until closure. */
static int close_event(tlv_tree_reader_t* reader, tlv_tree_event_t* event) {
    tlv_tree_frame_t frame;
    if (reader->end_pending) {
        frame = reader->pending;
        event->skipped = reader->skipped;
        reader->end_pending = reader->skipped = 0;
        event->depth = reader->depth;
    } else if (!reader->descend_pending && reader->depth &&
               tlv_reader_offset(&reader->input) == reader->frames[reader->depth - 1].end) {
        frame = reader->frames[--reader->depth];
        event->depth = reader->depth;
    } else {
        return 0;
    }
    event->kind = TLV_TREE_END;
    event->offset = frame.end;
    reader->input.pos = frame.resume - reader->input.base_offset;
    return 1;
}

static void drain_ends(tlv_tree_reader_t* reader) {
    tlv_tree_event_t event = {0};
    while (close_event(reader, &event)) {
    }
}

tlv_result_t tlv_tree_reader_init(tlv_tree_reader_t* reader, const uint8_t* data, size_t size,
                                  const tlv_format_t* format, tlv_tree_frame_t* frames,
                                  size_t capacity, size_t max_depth, size_t max_elements) {
    tlv_tree_reader_t initialized = {0};
    tlv_result_t rc;
    if (!reader || (!frames && capacity)) return TLV_ERR_NULL_ARG;
    rc = tlv_reader_init(&initialized.input, data, size, format);
    if (rc != TLV_OK) return rc;
    initialized.frames = frames;
    initialized.capacity = capacity;
    initialized.max_depth = max_depth;
    initialized.max_elements = max_elements;
    *reader = initialized;
    return TLV_OK;
}

tlv_result_t tlv_tree_reader_init_incremental(tlv_tree_reader_t* reader, const uint8_t* data,
                                              size_t size, const tlv_format_t* format,
                                              tlv_tree_frame_t* frames, size_t capacity,
                                              size_t max_depth, size_t max_elements) {
    tlv_result_t rc =
        tlv_tree_reader_init(reader, data, size, format, frames, capacity, max_depth, max_elements);
    if (rc == TLV_OK) reader->input.final_input = 0;
    return rc;
}

tlv_result_t tlv_tree_reader_set_input(tlv_tree_reader_t* reader, const uint8_t* data, size_t size,
                                       size_t discard, int final_input) {
    if (!reader) return TLV_ERR_NULL_ARG;
    return tlv_reader_set_input(&reader->input, data, size, discard, final_input);
}

size_t tlv_tree_reader_consumed(const tlv_tree_reader_t* reader) {
    return reader ? tlv_reader_consumed(&reader->input) : 0;
}

size_t tlv_tree_reader_offset(const tlv_tree_reader_t* reader) {
    return reader ? tlv_reader_offset(&reader->input) : 0;
}

int tlv_tree_reader_at_end(const tlv_tree_reader_t* reader) {
    return reader && !reader->descend_pending && !reader->end_pending && !reader->depth &&
           tlv_reader_at_end(&reader->input);
}

tlv_result_t tlv_tree_reader_next_event_diag(tlv_tree_reader_t* reader, tlv_tree_event_t* item,
                                             tlv_reader_diagnostic_t* diagnostic) {
    tlv_reader_t input;
    tlv_tree_event_t next = {0};
    int constructed;
    size_t depth;
    tlv_result_t rc;
    if (!reader || !item) return TLV_ERR_NULL_ARG;
    if (close_event(reader, &next)) {
        reader->item_projection = 0;
        *item = next;
        return TLV_OK;
    }
    input = reader->input;
    depth = reader->depth;
    if (reader->descend_pending) {
        if (depth == reader->max_depth || depth == reader->capacity) return TLV_ERR_LIMIT;
        ++depth;
        input.size = reader->pending.end - input.base_offset;
        input.final_input = 1;
    } else if (depth) {
        input.size = reader->frames[depth - 1].end - input.base_offset;
        input.final_input = 1;
    }
    if (input.pos < input.size && reader->count == reader->max_elements) return TLV_ERR_LIMIT;
    next.offset = tlv_reader_offset(&input);
    next.depth = depth;
    rc = tlv_reader_next_source_diag(&input, &next.element, &next.source, diagnostic);
    if (rc != TLV_OK) return rc;
    constructed = input.format->is_constructed &&
                  input.format->is_constructed(input.format->context, &next.element.tag);
    if (reader->descend_pending) reader->frames[reader->depth] = reader->pending;
    reader->depth = depth;
    reader->input.pos = input.pos;
    ++reader->count;
    next.kind = constructed ? TLV_TREE_BEGIN : TLV_TREE_ELEMENT;
    reader->item_projection = 0;
    reader->descend_pending = constructed && next.element.value.size;
    reader->end_pending = constructed && !next.element.value.size;
    if (constructed) {
        const size_t start = next.offset + next.source.value.offset;
        reader->pending.end = start + next.source.value.size;
        reader->pending.resume = tlv_reader_offset(&input);
        reader->input.pos = start - input.base_offset;
    }
    *item = next;
    return TLV_OK;
}

tlv_result_t tlv_tree_reader_next_event(tlv_tree_reader_t* reader, tlv_tree_event_t* event) {
    return tlv_tree_reader_next_event_diag(reader, event, NULL);
}

tlv_result_t tlv_tree_reader_next_diag(tlv_tree_reader_t* reader, tlv_tree_item_t* item,
                                       tlv_reader_diagnostic_t* diagnostic) {
    tlv_tree_event_t event;
    tlv_result_t rc;
    if (!reader || !item) return TLV_ERR_NULL_ARG;
    do {
        rc = tlv_tree_reader_next_event_diag(reader, &event, diagnostic);
        if (rc != TLV_OK) return rc;
    } while (event.kind == TLV_TREE_END);
    *item = (tlv_tree_item_t){event.element, event.source, event.depth, event.offset,
                              event.kind == TLV_TREE_BEGIN};
    reader->item_projection = 1;
    drain_ends(reader);
    return TLV_OK;
}

tlv_result_t tlv_tree_reader_next(tlv_tree_reader_t* reader, tlv_tree_item_t* item) {
    return tlv_tree_reader_next_diag(reader, item, NULL);
}

tlv_result_t tlv_tree_reader_skip_subtree(tlv_tree_reader_t* reader) {
    if (!reader) return TLV_ERR_NULL_ARG;
    if (!reader->descend_pending) return TLV_ERR_INVALID_ARG;
    reader->input.pos = reader->pending.resume - reader->input.base_offset;
    reader->descend_pending = 0;
    reader->end_pending = reader->skipped = 1;
    if (reader->item_projection) drain_ends(reader);
    return TLV_OK;
}
