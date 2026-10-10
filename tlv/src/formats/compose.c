// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv/formats/compose.h"
#include "../field/fixed_internal.h"
#include "../callback_internal.h"
#include "tlv/size.h"
#include <string.h>

static tlv_range_t range(size_t offset, size_t size) {
    tlv_range_t r = {offset, size, 1};
    return r;
}

/* A field extent clipped to the available input, also for a failed field. */
static tlv_range_t available(size_t offset, size_t used, size_t size) {
    return range(offset, used <= size - offset ? used : size - offset);
}

/* Successful operations never write error; failures publish detail from state already held. */
static tlv_result_t failure(tlv_format_error_t* e, tlv_result_t rc, tlv_region_t region,
                            size_t offset) {
    e->region = region;
    e->offset = offset;
    e->has_offset = 1;
    return rc;
}

static tlv_result_t fields_failure(tlv_format_error_t* e, const tlv_decoded_t* result,
                                   tlv_result_t rc, tlv_region_t region, size_t offset) {
    e->tag = result->source.tag;
    e->length = result->source.length;
    return failure(e, rc, region, offset);
}

tlv_result_t tlv_fields_decode(const void* context, const uint8_t* data, size_t size,
                               tlv_decoded_t* result, tlv_format_error_t* error) {
    const tlv_field_composition_t* f = (const tlv_field_composition_t*)context;
    tlv_tag_t tag = {0};
    tlv_size_t length = 0;
    size_t pos = 0, tag_size = 0, length_size = 0, trailer = 0, native;
    tlv_result_t rc;
    for (int step = 0; step < 2; ++step) {
        int identifier = (step == 0) == (f->element_order == TLV_ELEMENT_ORDER_TLV);
        if (identifier) {
            rc = f->read_tag(f->context, data + pos, size - pos, &tag, &tag_size);
            rc = tlv_callback_result(rc, 0);
            if (rc == TLV_OK && (!tag_size || tag_size > size - pos || (tag.size && !tag.data)))
                rc = TLV_ERR_CALLBACK;
            if (rc != TLV_OK) return fields_failure(error, result, rc, TLV_REGION_TAG, pos);
            result->source.tag = range(pos, tag_size);
            pos += tag_size;
        } else {
            if (f->resolve) {
                tlv_format_error_t resolved = {0};
                rc = f->resolve(f->context, &tag, data + pos, size - pos, &length_size, &length,
                                &trailer, &resolved);
                rc = tlv_callback_result(rc, 0);
                if (rc != TLV_OK) {
                    result->source.length = available(pos, length_size, size);
                    fields_failure(error, result, rc, TLV_REGION_LENGTH, pos);
                    if (resolved.has_offset) {
                        error->region = resolved.region;
                        error->offset = pos + resolved.offset;
                        error->required = resolved.required;
                        error->has_required = resolved.has_required;
                    }
                    return rc;
                }
            } else {
                rc = f->read_length(f->context, data + pos, size - pos, &length, &length_size);
                rc = tlv_callback_result(rc, 0);
            }
            result->source.length = available(pos, length_size, size);
            if (rc == TLV_OK && length_size > size - pos) rc = TLV_ERR_CALLBACK;
            if (rc == TLV_OK && f->length_scope == TLV_LENGTH_SCOPE_TAG_AND_VALUE && !length)
                rc = TLV_ERR_INVALID_LENGTH;
            if (rc != TLV_OK) return fields_failure(error, result, rc, TLV_REGION_LENGTH, pos);
            pos += length_size;
        }
    }
    if (f->length_scope == TLV_LENGTH_SCOPE_TAG_AND_VALUE) {
        if (length < tag_size)
            return fields_failure(error, result, TLV_ERR_INVALID_LENGTH, TLV_REGION_LENGTH,
                                  result->source.length.offset);
        length -= tag_size;
    }
    if (length > size - pos) {
        error->required = length;
        error->has_required = 1;
        return fields_failure(error, result, TLV_ERR_TRUNCATED, TLV_REGION_VALUE, pos);
    }
    native = (size_t)length;
    if (trailer > size - pos - native) {
        error->required = trailer;
        error->has_required = 1;
        error->value = range(pos, native);
        return fields_failure(error, result, TLV_ERR_TRUNCATED, TLV_REGION_TRAILER, pos + native);
    }
    result->element.tag = tag;
    result->element.value = (tlv_value_t){data + pos, length};
    result->source.header = range(0, pos);
    result->source.value = range(pos, native);
    result->source.trailer = range(pos + native, trailer);
    result->source.size = pos + native + trailer;
    return TLV_OK;
}

static size_t length_offset(const tlv_field_composition_t* f, size_t tag_size) {
    return f->element_order == TLV_ELEMENT_ORDER_TLV ? tag_size : 0;
}

static tlv_result_t field_sizes(const tlv_field_composition_t* f, const tlv_element_t* element,
                                size_t* tag_size, size_t* length_size, tlv_size_t* count,
                                tlv_format_error_t* error) {
    tlv_result_t rc = f->write_tag(f->context, &element->tag, NULL, 0, tag_size);
    rc = tlv_callback_result(rc, 0);
    if (rc == TLV_OK && !*tag_size) rc = TLV_ERR_CALLBACK;
    if (rc != TLV_OK) return failure(error, rc, TLV_REGION_TAG, 0);
    *count = element->value.size;
    if (f->length_scope == TLV_LENGTH_SCOPE_TAG_AND_VALUE)
        rc = tlv_size_add(*count, *tag_size, count);
    if (rc == TLV_OK)
        rc = tlv_callback_result(f->write_length(f->context, *count, NULL, 0, length_size), 0);
    return rc == TLV_OK ? TLV_OK
                        : failure(error, rc, TLV_REGION_LENGTH, length_offset(f, *tag_size));
}

tlv_result_t tlv_fields_measure(const void* context, const tlv_element_t* element,
                                tlv_encoding_t* encoding, tlv_format_error_t* error) {
    const tlv_field_composition_t* f = (const tlv_field_composition_t*)context;
    size_t t = 0, l = 0;
    tlv_size_t count;
    tlv_result_t rc = field_sizes(f, element, &t, &l, &count, error);
    if (rc != TLV_OK) return rc;
    rc = tlv_size_add(t, l, &encoding->header);
    if (rc == TLV_OK) {
        encoding->value = element->value.size;
        encoding->trailer = 0;
        rc = tlv_size_add(encoding->header, encoding->value, &encoding->total);
    }
    return rc == TLV_OK ? TLV_OK : failure(error, rc, TLV_REGION_LENGTH, length_offset(f, t));
}

tlv_result_t tlv_fields_encode(const void* context, const tlv_element_t* element, uint8_t* data,
                               size_t capacity, size_t* written, tlv_format_error_t* error) {
    const tlv_field_composition_t* f = (const tlv_field_composition_t*)context;
    size_t t = 0, l = 0, v, used = 0, to, lo;
    tlv_size_t count;
    tlv_result_t rc = field_sizes(f, element, &t, &l, &count, error);
    if (rc != TLV_OK) return rc;
    to = f->element_order == TLV_ELEMENT_ORDER_TLV ? 0 : l;
    lo = length_offset(f, t);
    rc = tlv_size_to_native(element->value.size, &v);
    if (rc == TLV_OK && (t > capacity || l > capacity - t || v > capacity - t - l))
        rc = TLV_ERR_BUFFER_TOO_SHORT;
    if (rc != TLV_OK) return failure(error, rc, TLV_REGION_LENGTH, lo);
    rc = f->write_tag(f->context, &element->tag, data + to, t, &used);
    rc = tlv_callback_result(rc, 0);
    if (rc == TLV_OK && used != t) rc = TLV_ERR_CALLBACK;
    if (rc != TLV_OK) return failure(error, rc, TLV_REGION_TAG, to);
    rc = f->write_length(f->context, count, data + lo, l, &used);
    rc = tlv_callback_result(rc, 0);
    if (rc == TLV_OK && used != l) rc = TLV_ERR_CALLBACK;
    if (rc != TLV_OK) return failure(error, rc, TLV_REGION_LENGTH, lo);
    if (v) memcpy(data + t + l, element->value.data, v);
    *written = t + l + v;
    return TLV_OK;
}

tlv_result_t tlv_fields_format_init(tlv_format_t* format, const tlv_field_composition_t* f) {
    int read, write;
    if (!f ||
        (f->element_order != TLV_ELEMENT_ORDER_TLV && f->element_order != TLV_ELEMENT_ORDER_LTV) ||
        (f->length_scope != TLV_LENGTH_SCOPE_VALUE &&
         f->length_scope != TLV_LENGTH_SCOPE_TAG_AND_VALUE) ||
        (f->resolve &&
         (f->element_order != TLV_ELEMENT_ORDER_TLV || f->length_scope != TLV_LENGTH_SCOPE_VALUE)))
        return TLV_ERR_INVALID_ARG;
    read = f->read_tag || f->read_length || f->resolve;
    write = f->write_tag || f->write_length;
    if ((read && !(f->read_tag && f->read_length)) || (write && !(f->write_tag && f->write_length)))
        return TLV_ERR_INVALID_ARG;
    return tlv_format_init(format, f, read ? tlv_fields_decode : NULL,
                           write ? tlv_fields_measure : NULL, write ? tlv_fields_encode : NULL);
}

static tlv_result_t binary_tag_read(const void* ctx, const uint8_t* data, size_t size,
                                    tlv_tag_t* tag, size_t* used) {
    const tlv_binary_composition_t* f = (const tlv_binary_composition_t*)ctx;
    return tlv_fixed_identifier_read(&f->identifier, data, size, tag, used);
}

static tlv_result_t binary_tag_write(const void* ctx, const tlv_tag_t* tag, uint8_t* data,
                                     size_t capacity, size_t* used) {
    const tlv_binary_composition_t* f = (const tlv_binary_composition_t*)ctx;
    return tlv_fixed_identifier_write(&f->identifier, tag, data, capacity, used);
}

static tlv_result_t binary_length_read(const void* ctx, const uint8_t* data, size_t size,
                                       tlv_size_t* length, size_t* used) {
    const tlv_binary_composition_t* f = (const tlv_binary_composition_t*)ctx;
    return tlv_fixed_length_read(&f->length, data, size, length, used);
}

static tlv_result_t binary_length_write(const void* ctx, tlv_size_t length, uint8_t* data,
                                        size_t capacity, size_t* used) {
    const tlv_binary_composition_t* f = (const tlv_binary_composition_t*)ctx;
    return tlv_fixed_length_write(&f->length, length, data, capacity, used);
}

static tlv_field_composition_t binary_fields(const void* context) {
    const tlv_binary_composition_t* f = (const tlv_binary_composition_t*)context;
    tlv_field_composition_t fields = {
        context,          binary_tag_read,     binary_length_read, NULL,
        binary_tag_write, binary_length_write, f->element_order,   f->length_scope};
    return fields;
}

tlv_result_t tlv_binary_decode(const void* context, const uint8_t* data, size_t size,
                               tlv_decoded_t* result, tlv_format_error_t* error) {
    const tlv_binary_composition_t* composition = (const tlv_binary_composition_t*)context;
    tlv_field_composition_t f = binary_fields(context);
    tlv_result_t rc = tlv_fields_decode(&f, data, size, result, error);
    if (rc == TLV_ERR_TRUNCATED &&
        (error->region == TLV_REGION_TAG || error->region == TLV_REGION_LENGTH)) {
        error->has_required = 1;
        error->required = error->region == TLV_REGION_TAG ? composition->identifier.size
                                                          : composition->length.size;
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
    tlv_result_t rc = f->fields.read_tag(f->fields.context, data, size, &tag, &width);
    rc = tlv_callback_result(rc, 0);
    if (rc == TLV_OK && (!width || width > size || (tag.size && !tag.data))) rc = TLV_ERR_CALLBACK;
    if (rc != TLV_OK) return failure(error, rc, TLV_REGION_TAG, 0);
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
    tlv_result_t rc = f->fields.write_tag(f->fields.context, &element->tag, NULL, 0, &width);
    rc = tlv_callback_result(rc, 0);
    if (rc == TLV_OK && !width) rc = TLV_ERR_CALLBACK;
    if (rc != TLV_OK) return failure(error, rc, TLV_REGION_TAG, 0);
    if (!tagged_fields_tag_only(f, &element->tag))
        return tlv_fields_measure(&f->fields, element, encoding, error);
    if (element->value.size) {
        error->required = 0;
        error->has_required = 1;
        return failure(error, TLV_ERR_INVALID_LENGTH, TLV_REGION_VALUE, width);
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
    rc = encoding.total > capacity
             ? TLV_ERR_BUFFER_TOO_SHORT
             : f->fields.write_tag(f->fields.context, &element->tag, data, capacity, written);
    return rc == TLV_OK ? TLV_OK : failure(error, rc, TLV_REGION_TAG, 0);
}

tlv_result_t tlv_tagged_fields_format_init(tlv_format_t* format,
                                           const tlv_tagged_fields_composition_t* f) {
    if (!format || !f) return TLV_ERR_NULL_ARG;
    if (!f->fields.read_tag || !f->fields.read_length || !f->fields.write_tag ||
        !f->fields.write_length || f->fields.resolve ||
        f->fields.element_order != TLV_ELEMENT_ORDER_TLV ||
        f->fields.length_scope != TLV_LENGTH_SCOPE_VALUE || (f->count && !f->tag_only))
        return TLV_ERR_INVALID_ARG;
    for (size_t i = 0; i < f->count; ++i) {
        size_t width = 0;
        tlv_result_t rc;
        if (!f->tag_only[i].size || !f->tag_only[i].data) return TLV_ERR_INVALID_ARG;
        rc = f->fields.write_tag(f->fields.context, &f->tag_only[i], NULL, 0, &width);
        rc = tlv_callback_result(rc, 0);
        if (rc != TLV_OK) return rc;
        if (!width) return TLV_ERR_CALLBACK;
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
    if (rc == TLV_ERR_TRUNCATED &&
        (error->region == TLV_REGION_TAG || error->region == TLV_REGION_LENGTH)) {
        error->has_required = 1;
        error->required =
            error->region == TLV_REGION_TAG ? f->fields.identifier.size : f->fields.length.size;
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
    tlv_result_t rc;
    if (!format || !f) return TLV_ERR_NULL_ARG;
    rc = fixed_identifier_validate(&f->fields.identifier);
    if (rc != TLV_OK) return rc;
    rc = fixed_length_validate(&f->fields.length);
    if (rc != TLV_OK) return rc;
    if (f->fields.element_order != TLV_ELEMENT_ORDER_TLV ||
        f->fields.length_scope != TLV_LENGTH_SCOPE_VALUE || (f->count && !f->tag_only))
        return TLV_ERR_INVALID_ARG;
    for (size_t i = 0; i < f->count; ++i)
        if (!f->tag_only[i].data || f->tag_only[i].size != f->fields.identifier.size)
            return TLV_ERR_INVALID_ARG;
    return tlv_format_init(format, f, tlv_tagged_binary_decode, tlv_tagged_binary_measure,
                           tlv_tagged_binary_encode);
}
