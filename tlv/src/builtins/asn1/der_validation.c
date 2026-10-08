// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv/config.h"
#include "ber_internal.h"
#include "tlv/builtins/asn1/der.h"
#include "tlv/builtins/asn1/der_validation.h"
#include "tlv/writer/writer.h"
#include "tlv/size.h"
#include "der_validation_internal.h"
#include "asn1_values_internal.h"
#include <string.h>

const tlv_der_limits_t tlv_der_default_limits = {32, (size_t)16 * 1024 * 1024,
                                                 (size_t)16 * 1024 * 1024, 100000};

static tlv_result_t fail(tlv_result_t rc, size_t offset, tlv_diagnostic_t* diagnostic) {
    if (diagnostic) {
        tlv_diagnostic_init(diagnostic, rc, TLV_DIAGNOSTIC_SEVERITY_ERROR);
        tlv_diagnostic_set_location(diagnostic, TLV_LOCATION_INPUT, TLV_LOCATION_POINT, offset,
                                    offset);
    }
    return rc;
}

static tlv_result_t unlocated(tlv_result_t rc, tlv_diagnostic_t* diagnostic) {
    if (diagnostic) tlv_diagnostic_init(diagnostic, rc, TLV_DIAGNOSTIC_SEVERITY_ERROR);
    return rc;
}

/* Parse a bounded header with field offsets. No outputs escape on failure. */
tlv_result_t tlv_der_read_element(const uint8_t* data, size_t size, size_t base,
                                  const tlv_der_limits_t* limits, tlv_element_t* element,
                                  size_t* consumed, tlv_diagnostic_t* diagnostic) {
    size_t tag_size, length_size;
    tlv_size_t value_length;
    tlv_result_t rc = tlv_der_fields.read_tag(NULL, data, size, &element->tag, &tag_size);
    if (rc != TLV_OK) return fail(rc, base, diagnostic);
    rc = tlv_der_fields.read_length(NULL, data + tag_size, size - tag_size, &value_length,
                                    &length_size);
    if (rc != TLV_OK) return fail(rc, base + tag_size, diagnostic);
    if (value_length > limits->max_value_size)
        return fail(TLV_ERR_LIMIT, base + tag_size, diagnostic);
    if (value_length > size - tag_size - length_size)
        return fail(TLV_ERR_BUFFER_TOO_SHORT, base + tag_size + length_size, diagnostic);
    element->value.size = value_length;

    element->value.data = data + tag_size + length_size;
    *consumed = tag_size + length_size + (size_t)value_length;
    return TLV_OK;
}

/* Iterative depth-first traversal: each stack slot is an enclosing value end.
 * Parent ends also serve as resume positions; descendants cannot escape them.
 */
static tlv_result_t traverse(const uint8_t* data, size_t size, size_t base, size_t initial_depth,
                             size_t initial_count, const tlv_der_limits_t* limits,
                             tlv_der_visitor_t visitor, void* context, int one,
                             tlv_element_t* first, size_t* first_size, int strict,
                             tlv_diagnostic_t* diagnostic) {
    size_t ends[TLV_DER_MAX_DEPTH + 1];
    size_t level = 0, pos = 0, count = initial_count;
    ends[0] = size;
    while (pos < ends[level] || level) {
        tlv_element_t element;
        size_t used, end, value_length;
        tlv_result_t rc;
        if (pos == ends[level]) {
            --level;
            continue;
        }
        if (initial_depth + level > limits->max_depth || count == limits->max_elements)
            return fail(TLV_ERR_LIMIT, base + pos, diagnostic);
        rc = tlv_der_read_element(data + pos, ends[level] - pos, base + pos, limits, &element,
                                  &used, diagnostic);
        if (rc != TLV_OK) return rc;
        ++count;
        end = pos + used;
        rc = tlv_size_to_native(element.value.size, &value_length);
        if (rc != TLV_OK) return fail(rc, base + pos, diagnostic);
        if (strict && tlv_asn1_tag_class(&element.tag) == TLV_ASN1_UNIVERSAL &&
            !tlv_asn1_tag_is_constructed(&element.tag)) {
            uint64_t number;
            rc = tlv_der_tag_number(&element.tag, &number);
            if (rc == TLV_OK)
                rc = tlv_asn1_validate_universal_value(number, element.value.data, value_length);
            if (rc != TLV_OK) return fail(rc, base + end - value_length, diagnostic);
        }
        if (one && pos == 0) {
            *first = element;
            *first_size = used;
            ends[0] = end;
        }
        if (visitor) {
            tlv_visit_result_t visit =
                visitor(&element, initial_depth + level, base + pos, context);
            if (visit == TLV_VISIT_STOP) return TLV_OK;
            if (visit != TLV_VISIT_CONTINUE)
                return fail(visit == TLV_VISIT_ERROR ? TLV_ERR_VISITOR : TLV_ERR_CALLBACK,
                            base + pos, diagnostic);
        }
        if (tlv_asn1_tag_is_constructed(&element.tag) && element.value.size) {
            /* Report the first child's tag for a depth-limit failure. */
            pos = end - value_length;
            if (initial_depth + level == limits->max_depth)
                return fail(TLV_ERR_LIMIT, base + pos, diagnostic);
            ends[++level] = end;
        } else
            pos = end;
    }
    return TLV_OK;
}

static tlv_result_t visit_impl(const uint8_t* data, size_t size, const tlv_der_limits_t* limits,
                               tlv_der_visitor_t visitor, void* context, int strict,
                               tlv_diagnostic_t* diagnostic) {
    if (!limits) limits = &tlv_der_default_limits;
    if (!data && size) return unlocated(TLV_ERR_NULL_ARG, diagnostic);
    if (limits->max_depth > TLV_DER_MAX_DEPTH) return unlocated(TLV_ERR_UNSUPPORTED, diagnostic);
    if (size > limits->max_input_size) return unlocated(TLV_ERR_LIMIT, diagnostic);
    return traverse(data, size, 0, 0, 0, limits, visitor, context, 0, NULL, NULL, strict,
                    diagnostic);
}

tlv_result_t tlv_der_visit(const uint8_t* data, size_t size, const tlv_der_limits_t* limits,
                           tlv_der_visitor_t visitor, void* context, tlv_diagnostic_t* diagnostic) {
    return visit_impl(data, size, limits, visitor, context, 0, diagnostic);
}

tlv_result_t tlv_der_visit_strict(const uint8_t* data, size_t size, const tlv_der_limits_t* limits,
                                  tlv_der_visitor_t visitor, void* context,
                                  tlv_diagnostic_t* diagnostic) {
    return visit_impl(data, size, limits, visitor, context, 1, diagnostic);
}

static tlv_result_t read_impl(const uint8_t* data, size_t size, const tlv_der_limits_t* limits,
                              tlv_element_t* element, size_t* consumed, int strict,
                              tlv_diagnostic_t* diagnostic) {
    tlv_element_t result;
    size_t used;
    tlv_result_t rc;
    if (!limits) limits = &tlv_der_default_limits;
    if ((!data && size) || !element || !consumed) return unlocated(TLV_ERR_NULL_ARG, diagnostic);
    if (limits->max_depth > TLV_DER_MAX_DEPTH) return unlocated(TLV_ERR_UNSUPPORTED, diagnostic);
    if (size > limits->max_input_size) return unlocated(TLV_ERR_LIMIT, diagnostic);
    if (!size) return fail(TLV_ERR_END_OF_BUFFER, 0, diagnostic);
    rc = traverse(data, size, 0, 0, 0, limits, NULL, NULL, 1, &result, &used, strict, diagnostic);
    if (rc == TLV_OK) {
        *element = result;
        *consumed = used;
    }
    return rc;
}

tlv_result_t tlv_der_read(const uint8_t* data, size_t size, const tlv_der_limits_t* limits,
                          tlv_element_t* element, size_t* consumed, tlv_diagnostic_t* diagnostic) {
    return read_impl(data, size, limits, element, consumed, 0, diagnostic);
}

tlv_result_t tlv_der_read_strict(const uint8_t* data, size_t size, const tlv_der_limits_t* limits,
                                 tlv_element_t* element, size_t* consumed,
                                 tlv_diagnostic_t* diagnostic) {
    return read_impl(data, size, limits, element, consumed, 1, diagnostic);
}

#if OPENTLV_WRITER
static tlv_result_t write_impl(uint8_t* data, size_t capacity, tlv_tag_t tag, const uint8_t* value,
                               size_t length, const tlv_der_limits_t* limits, int strict,
                               size_t* written, tlv_diagnostic_t* diagnostic) {
    size_t total;
    tlv_result_t rc;
    if (!limits) limits = &tlv_der_default_limits;
    if ((!data && capacity) || (!value && length) || !written)
        return unlocated(TLV_ERR_NULL_ARG, diagnostic);
    rc = tlv_encoded_size(tag, length, &tlv_format_der, &total);
    if (rc != TLV_OK) return fail(rc, rc == TLV_ERR_INVALID_LENGTH ? tag.size : 0, diagnostic);
    if (limits->max_depth > TLV_DER_MAX_DEPTH) return unlocated(TLV_ERR_UNSUPPORTED, diagnostic);
    if (total > limits->max_input_size || !limits->max_elements)
        return unlocated(TLV_ERR_LIMIT, diagnostic);
    if (length > limits->max_value_size) return fail(TLV_ERR_LIMIT, tag.size, diagnostic);
    if (strict && tlv_asn1_tag_class(&tag) == TLV_ASN1_UNIVERSAL &&
        !tlv_asn1_tag_is_constructed(&tag)) {
        uint64_t number;
        rc = tlv_der_tag_number(&tag, &number);
        if (rc == TLV_OK) rc = tlv_asn1_validate_universal_value(number, value, length);
        if (rc != TLV_OK) return fail(rc, total - length, diagnostic);
    }
    if (tlv_asn1_tag_is_constructed(&tag)) {
        rc = traverse(value, length, total - length, 1, 1, limits, NULL, NULL, 0, NULL, NULL,
                      strict, diagnostic);
        if (rc != TLV_OK) return rc;
    }
    if (!data) {
        *written = total;
        return TLV_OK;
    }
    rc = tlv_write(data, capacity, &tlv_format_der, tag, value, length, written);
    if (rc != TLV_OK) return unlocated(rc, diagnostic);
    return TLV_OK;
}

tlv_result_t tlv_der_write(uint8_t* data, size_t capacity, tlv_tag_t tag, const uint8_t* value,
                           size_t length, const tlv_der_limits_t* limits, size_t* written,
                           tlv_diagnostic_t* diagnostic) {
    tlv_result_t rc =
        write_impl(data, capacity, tag, value, length, limits, 0, written, diagnostic);
    if (rc != TLV_OK && diagnostic && diagnostic->location.kind != TLV_LOCATION_UNKNOWN)
        diagnostic->location.domain = TLV_LOCATION_OUTPUT;
    return rc;
}

tlv_result_t tlv_der_write_strict(uint8_t* data, size_t capacity, tlv_tag_t tag,
                                  const uint8_t* value, size_t length,
                                  const tlv_der_limits_t* limits, size_t* written,
                                  tlv_diagnostic_t* diagnostic) {
    tlv_result_t rc =
        write_impl(data, capacity, tag, value, length, limits, 1, written, diagnostic);
    if (rc != TLV_OK && diagnostic && diagnostic->location.kind != TLV_LOCATION_UNKNOWN)
        diagnostic->location.domain = TLV_LOCATION_OUTPUT;
    return rc;
}

#endif
