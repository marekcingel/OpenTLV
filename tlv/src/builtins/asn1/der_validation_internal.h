// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#ifndef OPENTLV_DER_VALIDATION_INTERNAL_H
#define OPENTLV_DER_VALIDATION_INTERNAL_H
#include "tlv/builtins/asn1/der_validation.h"
#include "tlv/element.h"
#include <stddef.h>
#include <stdint.h>

/* Parses one element's header (tag and length) from data[0..size), checking
 * it against limits->max_value_size and the available buffer. base is data's
 * absolute offset within the original input, used only to compute
 * error_offset. On success, *element holds the tag and a value borrowing data,
 * and *consumed is the complete element size (tag + length + value).
 * Outputs are unchanged on failure. Shared by tlv_der_read/visit/write's
 * traversal and the schema-aware DER validator/encoder. */
tlv_result_t tlv_der_read_element(const uint8_t* data, size_t size, size_t base,
                                  const tlv_der_limits_t* limits, tlv_element_t* element,
                                  size_t* consumed, tlv_diagnostic_t* diagnostic);

#endif /* OPENTLV_DER_VALIDATION_INTERNAL_H */
