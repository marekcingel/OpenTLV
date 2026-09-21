#include "tlv/formats/asn1/cer.h"
#include "tlv/profiles/cer.h"
#include "tlv/writer/writer.h"
#include "tlv/length.h"
#include "cer_values_internal.h"
#include <string.h>

const tlv_cer_limits_t tlv_cer_default_limits = {32, (size_t)16 * 1024 * 1024,
                                                 (size_t)16 * 1024 * 1024, 100000};

static tlv_result_t fail(tlv_result_t rc, size_t offset, size_t* error_offset) {
    if (error_offset) *error_offset = offset;
    return rc;
}

static int cer_number_must_construct(uint64_t number) {
    return number == 8 || number == 11 || number == 16 || number == 17 || number == 29;
}

/* One open indefinite (constructed) scope. Unlike DER's traverse(), which
 * needs a per-level end bound because a definite-length child can impose a
 * tighter bound than its parent, every CER constructed level shares the
 * same outer hard bound (the traverse() call's size): a level's true end is
 * only known once its EOC is found, so nothing tighter exists in between.
 * This also means there is no "resume" position to save separately: once a
 * level closes, scanning simply continues from just past its EOC, which is
 * already the loop's current position. */
typedef struct cer_level {
    tlv_tag_t tag;
    size_t tag_offset;    /* relative to this traverse() call's data */
    size_t length_offset; /* where the 0x80 length octet sits */
    size_t content_start;
    int segmentable;
    tlv_cer_segment_state_t segment_state;
} cer_level_t;

/* Resolves the segment-accumulator state (if any) that a child read at the
 * current depth belongs to: the enclosing level's, when depth > 0, or
 * outer_segments when depth == 0 -- the latter lets tlv_cer_write validate
 * pre-encoded children of a segmentable constructed value the same way
 * reading does, even though this call only ever sees those children, not
 * the constructed element's own tag/length that lives outside this buffer. */
static tlv_cer_segment_state_t* parent_segments(cer_level_t* levels, size_t depth,
                                                tlv_cer_segment_state_t* outer_segments) {
    if (depth > 0) return levels[depth - 1].segmentable ? &levels[depth - 1].segment_state : NULL;
    return outer_segments;
}

/* Iterative single-pass traversal: primitive elements (including string
 * segments) are visited immediately when read; a constructed element is
 * visited once its matching EOC is found (postorder), when its span is
 * finally known. base is the absolute offset of data[0] in the ultimate
 * input (used by tlv_cer_write's child-framing validation, which passes the
 * would-be output offset of the pre-encoded children). initial_depth offsets
 * reported visitor depths the same way. one/first/first_size implement
 * single-element reads: the loop returns as soon as the very first top-level
 * element (primitive or, once closed, constructed) is complete, without
 * inspecting further bytes. strict enables universal content validation.
 * outer_segments is non-NULL only from tlv_cer_write's constructed-child
 * validation, when the constructed element being written is itself a
 * segmentable UNIVERSAL type (see parent_segments()); base - 1 is then that
 * element's own would-be length-field offset, used if segmentation turns
 * out unjustified or absent once every child has been seen.
 */
static tlv_result_t traverse(const uint8_t* data, size_t size, size_t base, size_t initial_depth,
                             size_t initial_count, const tlv_cer_limits_t* limits,
                             tlv_cer_visitor_t visitor, void* context, int one, tlv_view_t* first,
                             size_t* first_size, int strict,
                             tlv_cer_segment_state_t* outer_segments, size_t* error_offset) {
    cer_level_t levels[TLV_CER_MAX_DEPTH];
    size_t depth = 0, pos = 0, count = initial_count;
    for (;;) {
        size_t elem_start, tag_size, length_offset;
        tlv_tag_t tag;
        tlv_result_t rc;
        tlv_asn1_class_t tag_class;
        int recognized_universal = 0, must_construct = 0;
        uint64_t number = 0;
        tlv_cer_type_info_t info = {TLV_CER_FORM_PRIMITIVE_ONLY, 1, 0};

        if (pos == size) {
            if (depth == 0) {
                if (outer_segments) {
                    size_t seg_err = 0;
                    rc = tlv_cer_segment_state_finish(outer_segments, base - 1, &seg_err);
                    if (rc != TLV_OK) return fail(rc, seg_err, error_offset);
                }
                return TLV_OK;
            }
            return fail(TLV_ERR_BUFFER_TOO_SHORT, base + levels[depth - 1].length_offset,
                        error_offset);
        }

        if (data[pos] == 0) {
            cer_level_t* lvl;
            tlv_view_t cview;
            size_t value_len;
            if (size - pos < 2) return fail(TLV_ERR_BUFFER_TOO_SHORT, base + pos, error_offset);
            if (data[pos + 1] != 0) return fail(TLV_ERR_INVALID_LENGTH, base + pos, error_offset);
            if (depth == 0) return fail(TLV_ERR_INVALID_TAG, base + pos, error_offset);
            lvl = &levels[depth - 1];
            value_len = pos - lvl->content_start;
            if (value_len > limits->max_value_size)
                return fail(TLV_ERR_LIMIT, base + lvl->length_offset, error_offset);
            if (lvl->segmentable) {
                size_t seg_err = 0;
                rc = tlv_cer_segment_state_finish(&lvl->segment_state, base + lvl->length_offset,
                                                  &seg_err);
                if (rc != TLV_OK) return fail(rc, seg_err, error_offset);
            }
            {
                tlv_length_t vlen;
                rc = tlv_length_from_size(value_len, &vlen);
                if (rc != TLV_OK) return fail(rc, base + lvl->length_offset, error_offset);
                cview.value.length = vlen;
            }
            cview.tag = lvl->tag;
            cview.value.data = data + lvl->content_start;
            pos += 2;
            --depth;
            if (visitor) {
                tlv_visit_result_t v =
                    visitor(&cview, initial_depth + depth, base + lvl->tag_offset, context);
                if (v == TLV_VISIT_STOP) return TLV_OK;
                if (v != TLV_VISIT_CONTINUE)
                    return fail(TLV_ERR_VISITOR, base + lvl->tag_offset, error_offset);
            }
            if (one && depth == 0) {
                *first = cview;
                *first_size = pos;
                return TLV_OK;
            }
            continue;
        }

        if (count == limits->max_elements) return fail(TLV_ERR_LIMIT, base + pos, error_offset);
        elem_start = pos;
        rc = tlv_reader_format_cer.read_tag(NULL, data + pos, size - pos, &tag, &tag_size);
        if (rc != TLV_OK) return fail(rc, base + pos, error_offset);
        pos += tag_size;
        length_offset = pos;
        if (pos == size) return fail(TLV_ERR_BUFFER_TOO_SHORT, base + length_offset, error_offset);

        tag_class = tlv_cer_tag_class(&tag);
        if (tag_class == TLV_ASN1_UNIVERSAL) {
            rc = tlv_cer_tag_number(&tag, &number);
            if (rc == TLV_OK && number <= 36) {
                recognized_universal = 1;
                must_construct = cer_number_must_construct(number);
                info = tlv_cer_type_info(number);
            }
        }

        if (data[pos] == 0x80) {
            /* Constructed, indefinite: push a new level and descend. */
            if (!tlv_cer_tag_is_constructed(&tag))
                return fail(TLV_ERR_INVALID_LENGTH, base + length_offset, error_offset);
            /* A segment must always be primitive; a constructed element
             * where a segment was expected is a prohibited nested-segment
             * arrangement, regardless of its own tag or type eligibility. */
            if (parent_segments(levels, depth, outer_segments))
                return fail(TLV_ERR_INVALID_TAG, base + elem_start, error_offset);
            if (recognized_universal && !must_construct && info.form == TLV_CER_FORM_PRIMITIVE_ONLY)
                return fail(TLV_ERR_INVALID_LENGTH, base + length_offset, error_offset);
            if (initial_depth + depth == limits->max_depth)
                return fail(TLV_ERR_LIMIT, base + elem_start, error_offset);
            ++count;
            {
                cer_level_t* lvl = &levels[depth];
                lvl->tag = tag;
                lvl->tag_offset = elem_start;
                lvl->length_offset = length_offset;
                lvl->content_start = pos + 1;
                lvl->segmentable = recognized_universal && !must_construct &&
                                   info.form != TLV_CER_FORM_PRIMITIVE_ONLY;
                if (lvl->segmentable)
                    tlv_cer_segment_state_init(&lvl->segment_state, number, info, strict);
            }
            pos = levels[depth].content_start;
            ++depth;
            continue;
        }

        /* Primitive: definite, canonically minimal length. */
        if (tlv_cer_tag_is_constructed(&tag))
            return fail(TLV_ERR_INVALID_LENGTH, base + length_offset, error_offset);
        {
            size_t value_length, length_size;
            const uint8_t* value_ptr;
            tlv_view_t view;
            rc = tlv_reader_format_cer.read_length(NULL, data + pos, size - pos, &value_length,
                                                   &length_size);
            if (rc != TLV_OK) return fail(rc, base + length_offset, error_offset);
            pos += length_size;
            if (value_length > size - pos)
                return fail(TLV_ERR_BUFFER_TOO_SHORT, base + pos, error_offset);
            value_ptr = data + pos;
            ++count;

            tlv_cer_segment_state_t* parent = parent_segments(levels, depth, outer_segments);
            if (parent) {
                size_t seg_err = 0;
                rc = tlv_cer_segment_state_add(parent, &tag, value_ptr, value_length,
                                               base + elem_start, &seg_err);
                if (rc != TLV_OK) return fail(rc, seg_err, error_offset);
            } else {
                if (value_length > limits->max_value_size)
                    return fail(TLV_ERR_LIMIT, base + length_offset, error_offset);
                if (recognized_universal) {
                    if (info.form != TLV_CER_FORM_PRIMITIVE_ONLY &&
                        value_length > TLV_CER_MAX_SEGMENT_OCTETS)
                        return fail(TLV_ERR_INVALID_LENGTH, base + length_offset, error_offset);
                    if (strict) {
                        rc = tlv_cer_validate_universal_value(number, value_ptr, value_length);
                        if (rc != TLV_OK) return fail(rc, base + pos, error_offset);
                    }
                }
            }

            view.tag = tag;
            {
                tlv_length_t vlen;
                rc = tlv_length_from_size(value_length, &vlen);
                if (rc != TLV_OK) return fail(rc, base + length_offset, error_offset);
                view.value.length = vlen;
            }
            view.value.data = value_ptr;
            pos += value_length;
            if (one && depth == 0) {
                *first = view;
                *first_size = pos;
                return TLV_OK;
            }
            if (visitor) {
                tlv_visit_result_t v =
                    visitor(&view, initial_depth + depth, base + elem_start, context);
                if (v == TLV_VISIT_STOP) return TLV_OK;
                if (v != TLV_VISIT_CONTINUE)
                    return fail(TLV_ERR_VISITOR, base + elem_start, error_offset);
            }
        }
    }
}

static tlv_result_t walk_impl(const uint8_t* data, size_t size, const tlv_cer_limits_t* limits,
                              tlv_cer_visitor_t visitor, void* context, int strict,
                              size_t* error_offset) {
    if (!limits) limits = &tlv_cer_default_limits;
    if (!data && size) return fail(TLV_ERR_NULL_ARG, 0, error_offset);
    if (limits->max_depth > TLV_CER_MAX_DEPTH || size > limits->max_input_size)
        return fail(TLV_ERR_LIMIT, 0, error_offset);
    return traverse(data, size, 0, 0, 0, limits, visitor, context, 0, NULL, NULL, strict, NULL,
                    error_offset);
}

tlv_result_t tlv_cer_walk(const uint8_t* data, size_t size, const tlv_cer_limits_t* limits,
                          tlv_cer_visitor_t visitor, void* context, size_t* error_offset) {
    return walk_impl(data, size, limits, visitor, context, 0, error_offset);
}

tlv_result_t tlv_cer_walk_strict(const uint8_t* data, size_t size, const tlv_cer_limits_t* limits,
                                 tlv_cer_visitor_t visitor, void* context, size_t* error_offset) {
    return walk_impl(data, size, limits, visitor, context, 1, error_offset);
}

static tlv_result_t read_impl(const uint8_t* data, size_t size, const tlv_cer_limits_t* limits,
                              tlv_view_t* view, size_t* consumed, int strict,
                              size_t* error_offset) {
    tlv_view_t result;
    size_t used;
    tlv_result_t rc;
    if (!limits) limits = &tlv_cer_default_limits;
    if ((!data && size) || !view || !consumed) return fail(TLV_ERR_NULL_ARG, 0, error_offset);
    if (limits->max_depth > TLV_CER_MAX_DEPTH || size > limits->max_input_size)
        return fail(TLV_ERR_LIMIT, 0, error_offset);
    if (!size) return fail(TLV_ERR_END_OF_BUFFER, 0, error_offset);
    rc = traverse(data, size, 0, 0, 0, limits, NULL, NULL, 1, &result, &used, strict, NULL,
                  error_offset);
    if (rc == TLV_OK) {
        *view = result;
        *consumed = used;
    }
    return rc;
}

tlv_result_t tlv_cer_read(const uint8_t* data, size_t size, const tlv_cer_limits_t* limits,
                          tlv_view_t* view, size_t* consumed, size_t* error_offset) {
    return read_impl(data, size, limits, view, consumed, 0, error_offset);
}

tlv_result_t tlv_cer_read_strict(const uint8_t* data, size_t size, const tlv_cer_limits_t* limits,
                                 tlv_view_t* view, size_t* consumed, size_t* error_offset) {
    return read_impl(data, size, limits, view, consumed, 1, error_offset);
}

/* Validates and, in strict mode, checks universal content of one primitive
 * value about to be written; shared by write_impl and
 * tlv_cer_write_segmented_string's single-primitive-element path. Returns
 * TLV_ERR_INVALID_LENGTH if a segmentable UNIVERSAL type's content exceeds
 * TLV_CER_MAX_SEGMENT_OCTETS as a bare primitive (a structural rule, checked
 * unconditionally). offset_base is where this element's length field would
 * sit in the eventual output, used for error_offset. */
static tlv_result_t check_primitive_value(tlv_tag_t tag, const uint8_t* value, size_t length,
                                          size_t offset_base, int strict, size_t* error_offset) {
    tlv_result_t rc;
    uint64_t number;
    if (tlv_cer_tag_class(&tag) != TLV_ASN1_UNIVERSAL) return TLV_OK;
    if (tlv_cer_tag_number(&tag, &number) != TLV_OK || number > 36) return TLV_OK;
    {
        tlv_cer_type_info_t info = tlv_cer_type_info(number);
        if (info.form != TLV_CER_FORM_PRIMITIVE_ONLY && length > TLV_CER_MAX_SEGMENT_OCTETS)
            return fail(TLV_ERR_INVALID_LENGTH, offset_base, error_offset);
    }
    if (!strict) return TLV_OK;
    rc = tlv_cer_validate_universal_value(number, value, length);
    if (rc != TLV_OK) return fail(rc, offset_base, error_offset);
    return TLV_OK;
}

static tlv_result_t write_impl(uint8_t* data, size_t capacity, tlv_tag_t tag, const uint8_t* value,
                               size_t length, const tlv_cer_limits_t* limits, int strict,
                               size_t* written, size_t* error_offset) {
    tlv_result_t rc;
    size_t tag_size;
    if (!limits) limits = &tlv_cer_default_limits;
    if ((!data && capacity) || (!value && length) || !written)
        return fail(TLV_ERR_NULL_ARG, 0, error_offset);
    if (limits->max_depth > TLV_CER_MAX_DEPTH || !limits->max_elements)
        return fail(TLV_ERR_LIMIT, 0, error_offset);
    rc = tlv_writer_format_cer.write_tag(NULL, NULL, 0, &tag, &tag_size);
    if (rc != TLV_OK) return fail(rc, 0, error_offset);

    if (tlv_cer_tag_is_constructed(&tag)) {
        size_t total;
        tlv_cer_segment_state_t outer_state;
        tlv_cer_segment_state_t* outer_segments = NULL;
        if (length > SIZE_MAX - tag_size - 3) return fail(TLV_ERR_INVALID_LENGTH, 0, error_offset);
        total = tag_size + 1 + length + 2;
        if (total > limits->max_input_size) return fail(TLV_ERR_LIMIT, 0, error_offset);
        /* When the element being written is itself a segmentable UNIVERSAL
         * type, validate its pre-encoded children as canonical segments the
         * same way reading does (see parent_segments()/traverse()). */
        if (tlv_cer_tag_class(&tag) == TLV_ASN1_UNIVERSAL) {
            uint64_t number;
            if (tlv_cer_tag_number(&tag, &number) == TLV_OK && number <= 36 &&
                !cer_number_must_construct(number)) {
                tlv_cer_type_info_t info = tlv_cer_type_info(number);
                if (info.form != TLV_CER_FORM_PRIMITIVE_ONLY) {
                    tlv_cer_segment_state_init(&outer_state, number, info, strict);
                    outer_segments = &outer_state;
                }
            }
        }
        rc = traverse(value, length, tag_size + 1, 1, 1, limits, NULL, NULL, 0, NULL, NULL, strict,
                      outer_segments, error_offset);
        if (rc != TLV_OK) return rc;
        if (!data) {
            *written = total;
            return TLV_OK;
        }
        if (capacity < total) return fail(TLV_ERR_BUFFER_TOO_SHORT, 0, error_offset);
        memcpy(data, tag.data, tag_size);
        data[tag_size] = 0x80;
        if (length) memcpy(data + tag_size + 1, value, length);
        data[total - 2] = 0;
        data[total - 1] = 0;
        *written = total;
        return TLV_OK;
    }

    if (length > limits->max_value_size) return fail(TLV_ERR_LIMIT, tag_size, error_offset);
    rc = check_primitive_value(tag, value, length, tag_size, strict, error_offset);
    if (rc != TLV_OK) return rc;
    {
        size_t total;
        rc = tlv_encoded_size(tag, length, &tlv_writer_format_cer, &total);
        if (rc != TLV_OK)
            return fail(rc, rc == TLV_ERR_INVALID_LENGTH ? tag_size : 0, error_offset);
        if (total > limits->max_input_size) return fail(TLV_ERR_LIMIT, 0, error_offset);
        if (!data) {
            *written = total;
            return TLV_OK;
        }
        rc = tlv_write(data, capacity, &tlv_writer_format_cer, tag, value, length, written);
        if (rc != TLV_OK) return fail(rc, 0, error_offset);
    }
    return TLV_OK;
}

tlv_result_t tlv_cer_write(uint8_t* data, size_t capacity, tlv_tag_t tag, const uint8_t* value,
                           size_t length, const tlv_cer_limits_t* limits, size_t* written,
                           size_t* error_offset) {
    return write_impl(data, capacity, tag, value, length, limits, 0, written, error_offset);
}

tlv_result_t tlv_cer_write_strict(uint8_t* data, size_t capacity, tlv_tag_t tag,
                                  const uint8_t* value, size_t length,
                                  const tlv_cer_limits_t* limits, size_t* written,
                                  size_t* error_offset) {
    return write_impl(data, capacity, tag, value, length, limits, 1, written, error_offset);
}

/* Source-octet layout for one call: num_non_final segments consuming
 * exactly chunk source octets each, plus one final segment of 1..chunk
 * source octets. chunk is TLV_CER_MAX_SEGMENT_OCTETS for OCTETS/CHARACTERS
 * (source octets equal segment content octets) or one less for BIT_STRING
 * (each segment's content also carries a separate synthesized/real
 * unused-bits octet, so only chunk=999 of the 1000 content octets come from
 * the source). Never leaves an unnecessary trailing empty final segment
 * when the source divides evenly. */
static void segment_layout(size_t total_octets, size_t chunk, size_t* num_non_final,
                           size_t* final_octets) {
    *num_non_final = (total_octets - 1) / chunk;
    *final_octets = total_octets - *num_non_final * chunk;
}

tlv_result_t tlv_cer_write_segmented_string(uint8_t* data, size_t capacity, tlv_tag_t tag,
                                            const uint8_t* content, size_t content_length,
                                            const tlv_cer_limits_t* limits, size_t* written,
                                            size_t* error_offset) {
    tlv_result_t rc;
    uint64_t number;
    tlv_cer_type_info_t info;
    size_t tag_size, seg_length_size;

    if (!limits) limits = &tlv_cer_default_limits;
    if ((!data && capacity) || (!content && content_length) || !written)
        return fail(TLV_ERR_NULL_ARG, 0, error_offset);
    if (limits->max_depth > TLV_CER_MAX_DEPTH || !limits->max_elements)
        return fail(TLV_ERR_LIMIT, 0, error_offset);
    if (tlv_cer_tag_class(&tag) != TLV_ASN1_UNIVERSAL || tlv_cer_tag_is_constructed(&tag))
        return fail(TLV_ERR_INVALID_ARG, 0, error_offset);
    rc = tlv_writer_format_cer.write_tag(NULL, NULL, 0, &tag, &tag_size);
    if (rc != TLV_OK) return fail(rc, 0, error_offset);
    if (tlv_cer_tag_number(&tag, &number) != TLV_OK || number > 36)
        return fail(TLV_ERR_INVALID_ARG, 0, error_offset);
    info = tlv_cer_type_info(number);
    if (info.form == TLV_CER_FORM_PRIMITIVE_ONLY) return fail(TLV_ERR_INVALID_ARG, 0, error_offset);

    rc = tlv_cer_validate_universal_value(number, content, content_length);
    if (rc != TLV_OK) return fail(rc, tag_size, error_offset);

    if (content_length <= TLV_CER_MAX_SEGMENT_OCTETS) {
        if (content_length > limits->max_value_size)
            return fail(TLV_ERR_LIMIT, tag_size, error_offset);
        {
            size_t total;
            rc = tlv_encoded_size(tag, content_length, &tlv_writer_format_cer, &total);
            if (rc != TLV_OK)
                return fail(rc, rc == TLV_ERR_INVALID_LENGTH ? tag_size : 0, error_offset);
            if (total > limits->max_input_size) return fail(TLV_ERR_LIMIT, 0, error_offset);
            if (!data) {
                *written = total;
                return TLV_OK;
            }
            rc = tlv_write(data, capacity, &tlv_writer_format_cer, tag, content, content_length,
                           written);
            if (rc != TLV_OK) return fail(rc, 0, error_offset);
        }
        return TLV_OK;
    }

    if (content_length > limits->max_value_size) return fail(TLV_ERR_LIMIT, tag_size, error_offset);
    rc = tlv_writer_format_cer.length_size(NULL, TLV_CER_MAX_SEGMENT_OCTETS, &seg_length_size);
    if (rc != TLV_OK) return fail(rc, 0, error_offset);

    {
        /* is_bit: every segment (including non-final ones, whose leading
         * byte is always the synthesized value 0) carries BIT STRING's
         * unused-bits octet separately from the source bit-content octets;
         * source_octets/chunk therefore exclude/reduce by that one byte. */
        int is_bit = info.form == TLV_CER_FORM_BIT_STRING;
        size_t chunk = is_bit ? TLV_CER_MAX_SEGMENT_OCTETS - 1 : TLV_CER_MAX_SEGMENT_OCTETS;
        size_t source_octets = is_bit ? content_length - 1 : content_length;
        size_t num_non_final, final_octets, final_content_size, final_length_size, total,
            per_segment;
        segment_layout(source_octets, chunk, &num_non_final, &final_octets);
        final_content_size = is_bit ? final_octets + 1 : final_octets;
        rc = tlv_writer_format_cer.length_size(NULL, final_content_size, &final_length_size);
        if (rc != TLV_OK) return fail(rc, 0, error_offset);

        per_segment = tag_size + seg_length_size + TLV_CER_MAX_SEGMENT_OCTETS;
        if (num_non_final > (SIZE_MAX - tag_size - 1 - 2) / per_segment)
            return fail(TLV_ERR_INVALID_LENGTH, 0, error_offset);
        total = tag_size + 1 + num_non_final * per_segment + 2;
        {
            size_t final_segment_size = tag_size + final_length_size + final_content_size;
            if (final_segment_size > SIZE_MAX - total)
                return fail(TLV_ERR_INVALID_LENGTH, 0, error_offset);
            total += final_segment_size;
        }
        if (total > limits->max_input_size) return fail(TLV_ERR_LIMIT, 0, error_offset);
        /* Elements written: the outer constructed element, num_non_final
         * segments, and the final segment. */
        if (num_non_final + 2 > limits->max_elements) return fail(TLV_ERR_LIMIT, 0, error_offset);

        if (!data) {
            *written = total;
            return TLV_OK;
        }
        if (capacity < total) return fail(TLV_ERR_BUFFER_TOO_SHORT, 0, error_offset);

        {
            uint8_t* out = data;
            const uint8_t* src = is_bit ? content + 1 : content;
            size_t used;
            /* Every currently segmentable type uses the single-byte
             * low-tag-number form, so the constructed wrapper tag is the
             * primitive tag with bit 0x20 set; segments below keep the
             * original primitive-form tag bytes. */
            memcpy(out, tag.data, tag_size);
            out[0] = (uint8_t)(out[0] | 0x20);
            out += tag_size;
            *out++ = 0x80;
            for (size_t i = 0; i < num_non_final; ++i) {
                memcpy(out, tag.data, tag_size);
                out += tag_size;
                rc = tlv_writer_format_cer.write_length(NULL, out, seg_length_size,
                                                        TLV_CER_MAX_SEGMENT_OCTETS, &used);
                if (rc != TLV_OK) return fail(rc, 0, error_offset);
                out += used;
                if (is_bit) *out++ = 0;
                memcpy(out, src, chunk);
                out += chunk;
                src += chunk;
            }
            memcpy(out, tag.data, tag_size);
            out += tag_size;
            rc = tlv_writer_format_cer.write_length(NULL, out, final_length_size,
                                                    final_content_size, &used);
            if (rc != TLV_OK) return fail(rc, 0, error_offset);
            out += used;
            if (is_bit) *out++ = content[0];
            if (final_octets) {
                memcpy(out, src, final_octets);
                out += final_octets;
            }
            *out++ = 0;
            *out++ = 0;
            *written = total;
        }
    }
    return TLV_OK;
}
