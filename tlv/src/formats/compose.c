// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv/formats/compose.h"
#include "tlv/field/fixed.h"
#include "tlv/size.h"
#include <string.h>

static tlv_range_t range(size_t offset, size_t size) {
    tlv_range_t r = {offset, size, 1};
    return r;
}

static void location(tlv_format_error_t* e, tlv_region_t region, size_t offset) {
    e->region = region;
    e->offset = offset;
    e->has_offset = 1;
}

tlv_result_t tlv_fields_decode(const void* context, const uint8_t* data, size_t size,
                               tlv_decoded_t* result, tlv_format_error_t* error) {
    const tlv_field_composition_t* f = (const tlv_field_composition_t*)context;
    tlv_tag_t tag = {0};
    tlv_size_t length = 0;
    size_t pos = 0, tag_size = 0, length_size = 0, trailer = 0, native;
    tlv_result_t rc;
    for (int step = 0; step < 2; ++step) {
        int identifier = (step == 0) == (f->order == TLV_ELEMENT_ORDER_TLV);
        if (identifier) {
            location(error, TLV_REGION_TAG, pos);
            rc = f->read_tag(f->context, data + pos, size - pos, &tag, &tag_size);
            if (rc != TLV_OK) return rc;
            if (!tag_size || tag_size > size - pos || (tag.size && !tag.data))
                return TLV_ERR_INVALID_TAG;
            error->tag = result->source.tag = range(pos, tag_size);
            pos += tag_size;
        } else {
            location(error, TLV_REGION_LENGTH, pos);
            if (f->resolve) {
                tlv_format_error_t resolved = {0};
                rc = f->resolve(f->context, &tag, data + pos, size - pos, &length_size, &length,
                                &trailer, &resolved);
                if (rc != TLV_OK && resolved.has_offset) {
                    error->region = resolved.region;
                    error->offset = pos + resolved.offset;
                    error->required = resolved.required;
                    error->has_required = resolved.has_required;
                }
            } else
                rc = f->read_length(f->context, data + pos, size - pos, &length, &length_size);
            error->length = range(pos, length_size <= size - pos ? length_size : size - pos);
            if (rc != TLV_OK) return rc;
            if (length_size > size - pos) return TLV_ERR_INVALID_LENGTH;
            if (f->scope == TLV_LENGTH_SCOPE_TAG_AND_VALUE && !length)
                return TLV_ERR_INVALID_LENGTH;
            result->source.length = error->length;
            pos += length_size;
        }
    }
    if (f->scope == TLV_LENGTH_SCOPE_TAG_AND_VALUE) {
        if (length < tag_size) {
            location(error, TLV_REGION_LENGTH, result->source.length.offset);
            return TLV_ERR_INVALID_LENGTH;
        }
        length -= tag_size;
    }
    location(error, TLV_REGION_VALUE, pos);
    error->required = length;
    error->has_required = 1;
    if (length > size - pos) return TLV_ERR_BUFFER_TOO_SHORT;
    native = (size_t)length;
    error->value = range(pos, native);
    location(error, TLV_REGION_TRAILER, pos + native);
    error->required = trailer;
    if (trailer > size - pos - native) return TLV_ERR_BUFFER_TOO_SHORT;
    result->element.tag = tag;
    result->element.value = (tlv_value_t){data + pos, length};
    result->source.header = range(0, pos);
    result->source.value = range(pos, native);
    result->source.trailer = range(pos + native, trailer);
    result->source.size = pos + native + trailer;
    return TLV_OK;
}

static tlv_result_t field_sizes(const tlv_field_composition_t* f, const tlv_element_t* element,
                                size_t* tag_size, size_t* length_size, tlv_size_t* count,
                                tlv_format_error_t* error) {
    tlv_result_t rc;
    location(error, TLV_REGION_TAG, 0);
    rc = f->write_tag(f->context, NULL, 0, &element->tag, tag_size);
    if (rc != TLV_OK) return rc;
    if (!*tag_size) return TLV_ERR_INVALID_TAG;
    *count = element->value.size;
    location(error, TLV_REGION_LENGTH, f->order == TLV_ELEMENT_ORDER_TLV ? *tag_size : 0);
    if (f->scope == TLV_LENGTH_SCOPE_TAG_AND_VALUE) {
        rc = tlv_size_add(*count, *tag_size, count);
        if (rc != TLV_OK) return rc;
    }
    return f->length_size(f->context, *count, length_size);
}

tlv_result_t tlv_fields_measure(const void* context, const tlv_element_t* element,
                                tlv_encoding_t* encoding, tlv_format_error_t* error) {
    const tlv_field_composition_t* f = (const tlv_field_composition_t*)context;
    size_t t = 0, l = 0;
    tlv_size_t count;
    tlv_result_t rc = field_sizes(f, element, &t, &l, &count, error);
    if (rc != TLV_OK) return rc;
    rc = tlv_size_add(t, l, &encoding->header);
    if (rc != TLV_OK) return rc;
    encoding->value = element->value.size;
    encoding->trailer = 0;
    return tlv_size_add(encoding->header, encoding->value, &encoding->total);
}

tlv_result_t tlv_fields_encode(const void* context, const tlv_element_t* element, uint8_t* data,
                               size_t capacity, size_t* written, tlv_format_error_t* error) {
    const tlv_field_composition_t* f = (const tlv_field_composition_t*)context;
    size_t t = 0, l = 0, v, used = 0, to, lo;
    tlv_size_t count;
    tlv_result_t rc = field_sizes(f, element, &t, &l, &count, error);
    if (rc != TLV_OK) return rc;
    rc = tlv_size_to_native(element->value.size, &v);
    if (rc != TLV_OK) return rc;
    if (t > capacity || l > capacity - t || v > capacity - t - l) return TLV_ERR_BUFFER_TOO_SHORT;
    to = f->order == TLV_ELEMENT_ORDER_TLV ? 0 : l;
    lo = f->order == TLV_ELEMENT_ORDER_TLV ? t : 0;
    location(error, TLV_REGION_TAG, to);
    rc = f->write_tag(f->context, data + to, t, &element->tag, &used);
    if (rc != TLV_OK) return rc;
    if (used != t) return TLV_ERR_INVALID_TAG;
    location(error, TLV_REGION_LENGTH, lo);
    rc = f->write_length(f->context, data + lo, l, count, &used);
    if (rc != TLV_OK) return rc;
    if (used != l) return TLV_ERR_INVALID_LENGTH;
    if (v) memcpy(data + t + l, element->value.data, v);
    *written = t + l + v;
    return TLV_OK;
}

tlv_result_t tlv_fields_format_init(tlv_format_t* format, const tlv_field_composition_t* f) {
    int read, write;
    if (!f || (f->order != TLV_ELEMENT_ORDER_TLV && f->order != TLV_ELEMENT_ORDER_LTV) ||
        (f->scope != TLV_LENGTH_SCOPE_VALUE && f->scope != TLV_LENGTH_SCOPE_TAG_AND_VALUE) ||
        (f->resolve && (f->order != TLV_ELEMENT_ORDER_TLV || f->scope != TLV_LENGTH_SCOPE_VALUE)))
        return TLV_ERR_INVALID_ARG;
    read = f->read_tag || f->read_length || f->resolve;
    write = f->write_tag || f->write_length || f->length_size;
    if ((read && !(f->read_tag && f->read_length)) ||
        (write && !(f->write_tag && f->write_length && f->length_size)))
        return TLV_ERR_INVALID_ARG;
    return tlv_format_init(format, f, read ? tlv_fields_decode : NULL,
                           write ? tlv_fields_measure : NULL, write ? tlv_fields_encode : NULL);
}

static tlv_result_t binary_tag_read(const void* ctx, const uint8_t* data, size_t size,
                                    tlv_tag_t* tag, size_t* used) {
    const tlv_binary_composition_t* f = (const tlv_binary_composition_t*)ctx;
    const tlv_fixed_identifier_t identifier = {f->tag_size};
    return tlv_fixed_identifier_read(&identifier, data, size, tag, used);
}

static tlv_result_t binary_tag_write(const void* ctx, uint8_t* data, size_t capacity,
                                     const tlv_tag_t* tag, size_t* used) {
    const tlv_binary_composition_t* f = (const tlv_binary_composition_t*)ctx;
    const tlv_fixed_identifier_t identifier = {f->tag_size};
    /* Composition historically reports width mismatch before missing tag bytes. */
    if (tag->size != f->tag_size) return TLV_ERR_INVALID_TAG_SIZE;
    return tlv_fixed_identifier_write(&identifier, tag, data, data ? capacity : 0, used);
}

static tlv_result_t binary_length_read(const void* ctx, const uint8_t* data, size_t size,
                                       tlv_size_t* length, size_t* used) {
    const tlv_binary_composition_t* f = (const tlv_binary_composition_t*)ctx;
    const tlv_fixed_length_t count = {f->length_size, f->length_order};
    /* Report the wire prefix before decoding, including on byte-order errors. */
    *used = size < f->length_size ? size : f->length_size;
    if (size < f->length_size) return TLV_ERR_BUFFER_TOO_SHORT;
    return tlv_fixed_length_read(&count, data, size, length, used);
}

static tlv_result_t binary_length_size(const void* ctx, tlv_size_t length, size_t* used) {
    const tlv_binary_composition_t* f = (const tlv_binary_composition_t*)ctx;
    /* A width query has never consulted wire byte order. The fixed primitive
     * validates its own configuration, so use a supported order for sizing. */
    const tlv_fixed_length_t count = {f->length_size, TLV_BYTE_ORDER_BIG_ENDIAN};
    return tlv_fixed_length_write(&count, length, NULL, 0, used);
}

static tlv_result_t binary_length_write(const void* ctx, uint8_t* data, size_t capacity,
                                        tlv_size_t length, size_t* used) {
    const tlv_binary_composition_t* f = (const tlv_binary_composition_t*)ctx;
    const tlv_fixed_length_t count = {f->length_size, f->length_order};
    /* Keep the published width on capacity/order errors, and preserve the
     * existing count-fit, capacity, byte-order validation precedence. */
    tlv_result_t rc = binary_length_size(ctx, length, used);
    if (rc != TLV_OK || !data) return rc;
    if (capacity < f->length_size) return TLV_ERR_BUFFER_TOO_SHORT;
    return tlv_fixed_length_write(&count, length, data, capacity, used);
}

static tlv_field_composition_t binary_fields(const void* context) {
    const tlv_binary_composition_t* f = (const tlv_binary_composition_t*)context;
    tlv_field_composition_t fields = {
        context,          binary_tag_read,     binary_length_read, NULL,
        binary_tag_write, binary_length_write, binary_length_size, f->element_order,
        f->length_scope};
    return fields;
}

tlv_result_t tlv_binary_decode(const void* context, const uint8_t* data, size_t size,
                               tlv_decoded_t* result, tlv_format_error_t* error) {
    const tlv_binary_composition_t* composition = (const tlv_binary_composition_t*)context;
    tlv_field_composition_t f = binary_fields(context);
    tlv_result_t rc = tlv_fields_decode(&f, data, size, result, error);
    if (rc == TLV_ERR_BUFFER_TOO_SHORT &&
        (error->region == TLV_REGION_TAG || error->region == TLV_REGION_LENGTH)) {
        error->has_required = 1;
        error->required =
            error->region == TLV_REGION_TAG ? composition->tag_size : composition->length_size;
    }
    return rc;
}

tlv_result_t tlv_binary_measure(const void* context, const tlv_element_t* element,
                                tlv_encoding_t* encoding, tlv_format_error_t* error) {
    tlv_field_composition_t f = binary_fields(context);
    return tlv_fields_measure(&f, element, encoding, error);
}

tlv_result_t tlv_binary_encode(const void* context, const tlv_element_t* element, uint8_t* data,
                               size_t capacity, size_t* written, tlv_format_error_t* error) {
    tlv_field_composition_t f = binary_fields(context);
    return tlv_fields_encode(&f, element, data, capacity, written, error);
}

static int tagged_fields_tag_only(const tlv_tagged_fields_composition_t* f, const tlv_tag_t* tag) {
    for (size_t i = 0; i < f->count; ++i)
        if (tlv_tag_equal(*tag, f->tag_only[i])) return 1;
    return 0;
}

tlv_result_t tlv_tagged_fields_decode(const void* context, const uint8_t* data, size_t size,
                                      tlv_decoded_t* result, tlv_format_error_t* error) {
    const tlv_tagged_fields_composition_t* f = (const tlv_tagged_fields_composition_t*)context;
    tlv_tag_t tag = {0};
    size_t width = 0;
    tlv_result_t rc;
    location(error, TLV_REGION_TAG, 0);
    rc = f->fields.read_tag(f->fields.context, data, size, &tag, &width);
    if (rc != TLV_OK) return rc;
    if (!width || width > size || (tag.size && !tag.data)) return TLV_ERR_INVALID_TAG;
    error->tag = range(0, width);
    if (!tagged_fields_tag_only(f, &tag))
        return tlv_fields_decode(&f->fields, data, size, result, error);
    result->element.tag = tag;
    result->element.value = (tlv_value_t){data + width, 0};
    result->source.header = range(0, width);
    result->source.tag = range(0, width);
    result->source.length = (tlv_range_t){0};
    result->source.value = range(width, 0);
    result->source.trailer = range(width, 0);
    result->source.size = width;
    return TLV_OK;
}

tlv_result_t tlv_tagged_fields_measure(const void* context, const tlv_element_t* element,
                                       tlv_encoding_t* encoding, tlv_format_error_t* error) {
    const tlv_tagged_fields_composition_t* f = (const tlv_tagged_fields_composition_t*)context;
    size_t width = 0;
    tlv_result_t rc;
    location(error, TLV_REGION_TAG, 0);
    rc = f->fields.write_tag(f->fields.context, NULL, 0, &element->tag, &width);
    if (rc != TLV_OK) return rc;
    if (!width) return TLV_ERR_INVALID_TAG;
    if (!tagged_fields_tag_only(f, &element->tag))
        return tlv_fields_measure(&f->fields, element, encoding, error);
    if (element->value.size) {
        location(error, TLV_REGION_VALUE, width);
        error->required = 0;
        error->has_required = 1;
        return TLV_ERR_INVALID_LENGTH;
    }
    *encoding = (tlv_encoding_t){width, 0, 0, width};
    return TLV_OK;
}

tlv_result_t tlv_tagged_fields_encode(const void* context, const tlv_element_t* element,
                                      uint8_t* data, size_t capacity, size_t* written,
                                      tlv_format_error_t* error) {
    const tlv_tagged_fields_composition_t* f = (const tlv_tagged_fields_composition_t*)context;
    tlv_encoding_t encoding;
    tlv_result_t rc = tlv_tagged_fields_measure(context, element, &encoding, error);
    if (rc != TLV_OK) return rc;
    if (!tagged_fields_tag_only(f, &element->tag))
        return tlv_fields_encode(&f->fields, element, data, capacity, written, error);
    if (encoding.total > capacity) return TLV_ERR_BUFFER_TOO_SHORT;
    return f->fields.write_tag(f->fields.context, data, capacity, &element->tag, written);
}

tlv_result_t tlv_tagged_fields_format_init(tlv_format_t* format,
                                           const tlv_tagged_fields_composition_t* f) {
    if (!format || !f) return TLV_ERR_NULL_ARG;
    if (!f->fields.read_tag || !f->fields.read_length || !f->fields.write_tag ||
        !f->fields.write_length || !f->fields.length_size || f->fields.resolve ||
        f->fields.order != TLV_ELEMENT_ORDER_TLV || f->fields.scope != TLV_LENGTH_SCOPE_VALUE ||
        (f->count && !f->tag_only))
        return TLV_ERR_INVALID_ARG;
    for (size_t i = 0; i < f->count; ++i) {
        size_t width = 0;
        tlv_result_t rc;
        if (!f->tag_only[i].size || !f->tag_only[i].data) return TLV_ERR_INVALID_ARG;
        rc = f->fields.write_tag(f->fields.context, NULL, 0, &f->tag_only[i], &width);
        if (rc != TLV_OK) return rc;
        if (!width) return TLV_ERR_INVALID_TAG;
    }
    return tlv_format_init(format, f, tlv_tagged_fields_decode, tlv_tagged_fields_measure,
                           tlv_tagged_fields_encode);
}

static tlv_tagged_fields_composition_t
tagged_binary_fields(const tlv_tagged_binary_composition_t* f) {
    tlv_tagged_fields_composition_t composition = {binary_fields(&f->fields), f->tag_only,
                                                   f->count};
    return composition;
}

tlv_result_t tlv_tagged_binary_decode(const void* context, const uint8_t* data, size_t size,
                                      tlv_decoded_t* result, tlv_format_error_t* error) {
    const tlv_tagged_binary_composition_t* f = (const tlv_tagged_binary_composition_t*)context;
    tlv_tagged_fields_composition_t fields = tagged_binary_fields(f);
    tlv_result_t rc = tlv_tagged_fields_decode(&fields, data, size, result, error);
    if (rc == TLV_ERR_BUFFER_TOO_SHORT &&
        (error->region == TLV_REGION_TAG || error->region == TLV_REGION_LENGTH)) {
        error->has_required = 1;
        error->required =
            error->region == TLV_REGION_TAG ? f->fields.tag_size : f->fields.length_size;
    }
    return rc;
}

tlv_result_t tlv_tagged_binary_measure(const void* context, const tlv_element_t* element,
                                       tlv_encoding_t* encoding, tlv_format_error_t* error) {
    tlv_tagged_fields_composition_t fields =
        tagged_binary_fields((const tlv_tagged_binary_composition_t*)context);
    return tlv_tagged_fields_measure(&fields, element, encoding, error);
}

tlv_result_t tlv_tagged_binary_encode(const void* context, const tlv_element_t* element,
                                      uint8_t* data, size_t capacity, size_t* written,
                                      tlv_format_error_t* error) {
    tlv_tagged_fields_composition_t fields =
        tagged_binary_fields((const tlv_tagged_binary_composition_t*)context);
    return tlv_tagged_fields_encode(&fields, element, data, capacity, written, error);
}

tlv_result_t tlv_tagged_binary_format_init(tlv_format_t* format,
                                           const tlv_tagged_binary_composition_t* f) {
    if (!format || !f) return TLV_ERR_NULL_ARG;
    if (!f->fields.tag_size || !f->fields.length_size || f->fields.length_size > 8 ||
        f->fields.element_order != TLV_ELEMENT_ORDER_TLV ||
        f->fields.length_scope != TLV_LENGTH_SCOPE_VALUE || (f->count && !f->tag_only))
        return TLV_ERR_INVALID_ARG;
    if (f->fields.length_order != TLV_BYTE_ORDER_BIG_ENDIAN &&
        f->fields.length_order != TLV_BYTE_ORDER_LITTLE_ENDIAN)
        return TLV_ERR_INVALID_BYTE_ORDER;
    for (size_t i = 0; i < f->count; ++i)
        if (!f->tag_only[i].data || f->tag_only[i].size != f->fields.tag_size)
            return TLV_ERR_INVALID_ARG;
    return tlv_format_init(format, f, tlv_tagged_binary_decode, tlv_tagged_binary_measure,
                           tlv_tagged_binary_encode);
}
