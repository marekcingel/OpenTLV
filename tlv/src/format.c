// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv/format.h"
#include "tlv/size.h"
#include <string.h>

int tlv_constructed_bit_predicate(const void* context, const tlv_tag_t* tag) {
    const tlv_constructed_bit_t* bit = (const tlv_constructed_bit_t*)context;
    return bit && bit->mask && !(bit->value & ~bit->mask) && tag && tag->data &&
           bit->byte_index < tag->size && (tag->data[bit->byte_index] & bit->mask) == bit->value;
}

tlv_result_t tlv_format_init(tlv_format_t* format, const void* context, tlv_decode_fn decode,
                             tlv_measure_fn measure, tlv_encode_fn encode) {
    if (!format || (!!measure != !!encode) || (!decode && !encode)) return TLV_ERR_INVALID_ARG;
    *format = (tlv_format_t){context, decode, measure, encode, NULL};
    return TLV_OK;
}

int tlv_format_can_read(const tlv_format_t* format) {
    return format && format->decode;
}

int tlv_format_can_write(const tlv_format_t* format) {
    return format && format->measure && format->encode;
}

static int range_valid(tlv_range_t r, size_t size) {
    return !r.present || (r.offset <= size && r.size <= size - r.offset);
}

static int bytes_equal(const uint8_t* a, const uint8_t* b, size_t size) {
    return !size || (a && b && memcmp(a, b, size) == 0);
}

static int tag_binding_valid(const tlv_decoded_t* result, const uint8_t* data) {
    const tlv_source_t* source = &result->source;
    const tlv_tag_t tag = result->element.tag;
    switch (source->tag_binding) {
        case TLV_TAG_BINDING_SOURCE:
            return source->tag.present
                       ? tag.size == source->tag.size && tag.data == data + source->tag.offset
                       : !tag.size && !tag.data;
        case TLV_TAG_BINDING_FORMAT:
            /* Storage extent and immutable lifetime are the callback's contract. */
            return tag.data != NULL;
        default: return 0;
    }
}

tlv_result_t tlv_format_decode(const tlv_format_t* format, const uint8_t* data, size_t size,
                               tlv_decoded_t* decoded, tlv_format_error_t* error) {
    tlv_decoded_t result = {0};
    tlv_format_error_t detail = {0};
    tlv_source_t* s = &result.source;
    tlv_result_t rc;
    if (!tlv_format_can_read(format) || !decoded || (!data && size)) return TLV_ERR_NULL_ARG;
    if (!size) {
        detail.has_offset = 1;
        if (error) *error = detail;
        return TLV_ERR_END_OF_BUFFER;
    }
    rc = format->decode(format->context, data, size, &result, &detail);
    if (rc == TLV_OK) {
        if (!s->header.present || !s->value.present || !s->trailer.present || !s->size ||
            s->size > size || s->header.offset != 0 || !range_valid(s->header, s->size) ||
            !range_valid(s->value, s->size) || !range_valid(s->trailer, s->size) ||
            !range_valid(s->tag, s->size) || !range_valid(s->length, s->size) ||
            s->value.offset != s->header.size ||
            s->trailer.offset != s->value.offset + s->value.size ||
            s->trailer.size != s->size - s->trailer.offset ||
            result.element.value.size != s->value.size ||
            result.element.value.data != data + s->value.offset ||
            !tag_binding_valid(&result, data))
            rc = TLV_ERR_INVALID_ARG;
    }
    if (rc != TLV_OK) {
        /* Never publish an out-of-buffer borrowed diagnostic range. */
        if (!range_valid(detail.tag, size)) detail.tag.present = 0;
        if (!range_valid(detail.length, size)) detail.length.present = 0;
        if (!range_valid(detail.value, size)) detail.value.present = 0;
        if (error) *error = detail;
        return rc;
    }
    s->data = data;
    s->format = format;
    s->element = result.element;
    *decoded = result;
    return TLV_OK;
}

tlv_result_t tlv_format_measure(const tlv_format_t* format, const tlv_element_t* element,
                                tlv_encoding_t* encoding, tlv_format_error_t* error) {
    tlv_encoding_t result = {0};
    tlv_format_error_t detail = {0};
    tlv_size_t total;
    tlv_result_t rc;
    if (!tlv_format_can_write(format) || !element || !encoding ||
        (element->tag.size && !element->tag.data))
        return TLV_ERR_NULL_ARG;
    rc = format->measure(format->context, element, &result, &detail);
    if (rc == TLV_OK) {
        rc = tlv_size_add(result.header, result.value, &total);
        if (rc == TLV_OK) rc = tlv_size_add(total, result.trailer, &total);
        if (rc == TLV_OK &&
            (!total || result.value != element->value.size || result.total != total))
            rc = TLV_ERR_INVALID_ARG;
    }
    if (rc != TLV_OK) {
        if (error) *error = detail;
        return rc;
    }
    *encoding = result;
    return TLV_OK;
}

tlv_result_t tlv_format_encode(const tlv_format_t* format, const tlv_element_t* element,
                               uint8_t* data, size_t capacity, size_t* written,
                               tlv_format_error_t* error) {
    tlv_encoding_t sizes;
    tlv_format_error_t detail = {0};
    size_t total, used = 0;
    tlv_result_t rc;
    if (!element || !written || (!data && capacity) ||
        (!element->value.data && element->value.size))
        return TLV_ERR_NULL_ARG;
    rc = tlv_format_measure(format, element, &sizes, error);
    if (rc != TLV_OK) return rc;
    rc = tlv_size_to_native(sizes.total, &total);
    if (rc != TLV_OK) return rc;
    if (capacity < total) {
        detail.region = TLV_REGION_VALUE;
        detail.has_offset = 1;
        detail.has_required = 1;
        detail.required = sizes.total;
        if (error) *error = detail;
        *written = total;
        return TLV_ERR_BUFFER_TOO_SHORT;
    }
    rc = format->encode(format->context, element, data, capacity, &used, &detail);
    if (rc == TLV_OK && used != total) rc = TLV_ERR_INVALID_LENGTH;
    if (rc != TLV_OK) {
        if (error) *error = detail;
        return rc;
    }
    *written = used;
    return TLV_OK;
}

tlv_result_t tlv_source_preserve(const tlv_source_t* source, const tlv_element_t* element,
                                 uint8_t* data, size_t capacity, size_t* written) {
    size_t size;
    tlv_result_t rc;
    if (!source || !element || !written || (!data && capacity) || !source->format || !source->data)
        return TLV_ERR_NULL_ARG;
    if ((!element->tag.size && (!!element->tag.data != !!source->element.tag.data)) ||
        element->tag.size != source->element.tag.size ||
        element->value.size != source->element.value.size)
        return TLV_ERR_INVALID_ARG;
    rc = tlv_size_to_native(element->value.size, &size);
    if (rc != TLV_OK) return rc;
    if (!bytes_equal(element->tag.data, source->element.tag.data, element->tag.size) ||
        !bytes_equal(element->value.data, source->element.value.data, size))
        return TLV_ERR_INVALID_ARG;
    if (data && capacity < source->size) {
        *written = source->size;
        return TLV_ERR_BUFFER_TOO_SHORT;
    }
    if (data) memmove(data, source->data, source->size);
    *written = source->size;
    return TLV_OK;
}
