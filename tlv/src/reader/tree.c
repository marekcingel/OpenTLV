#include "tlv/reader/tree.h"

/* Skip enclosing trailers using structural offsets, never retained Elements. */
static void close_scopes(tlv_tree_reader_t* reader) {
    while (reader->depth &&
           tlv_reader_offset(&reader->input) == reader->frames[reader->depth - 1].end) {
        reader->input.pos = reader->frames[--reader->depth].resume - reader->input.base_offset;
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
    return reader && !reader->descend_pending && !reader->depth &&
           tlv_reader_at_end(&reader->input);
}

tlv_result_t tlv_tree_reader_next_diag(tlv_tree_reader_t* reader, tlv_tree_item_t* item,
                                       tlv_reader_diagnostic_t* diagnostic) {
    tlv_reader_t input;
    tlv_tree_item_t next = {0};
    size_t depth;
    tlv_result_t rc;
    if (!reader || !item) return TLV_ERR_NULL_ARG;
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
    next.constructed = input.format->is_constructed &&
                       input.format->is_constructed(input.format->context, &next.element.tag);
    if (reader->descend_pending) reader->frames[reader->depth] = reader->pending;
    reader->depth = depth;
    reader->input.pos = input.pos;
    ++reader->count;
    reader->descend_pending = next.constructed && next.element.value.size;
    if (reader->descend_pending) {
        const size_t start = next.offset + next.source.value.offset;
        reader->pending.end = start + next.source.value.size;
        reader->pending.resume = tlv_reader_offset(&input);
        reader->input.pos = start - input.base_offset;
    } else {
        close_scopes(reader);
    }
    *item = next;
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
    close_scopes(reader);
    return TLV_OK;
}
