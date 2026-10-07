// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv/formats/fixed.h"
#include <stddef.h>

/* C99 alignment probe: a leading byte exposes the next member's alignment. */
struct identifier_alignment {
    char                   prefix;
    tlv_fixed_identifier_t value;
};
struct length_alignment {
    char               prefix;
    tlv_fixed_length_t value;
};
struct format_alignment {
    char               prefix;
    tlv_fixed_format_t value;
};

size_t opentlv_test_fixed_abi(size_t index) {
    const size_t values[] = {sizeof(tlv_fixed_identifier_t),
                             offsetof(struct identifier_alignment, value),
                             offsetof(tlv_fixed_identifier_t, size),
                             sizeof(tlv_fixed_length_t),
                             offsetof(struct length_alignment, value),
                             offsetof(tlv_fixed_length_t, size),
                             offsetof(tlv_fixed_length_t, byte_order),
                             sizeof(tlv_fixed_format_t),
                             offsetof(struct format_alignment, value),
                             offsetof(tlv_fixed_format_t, identifier),
                             offsetof(tlv_fixed_format_t, length),
                             offsetof(tlv_fixed_format_t, element_order),
                             offsetof(tlv_fixed_format_t, length_scope)};
    return index < sizeof values / sizeof values[0] ? values[index] : SIZE_MAX;
}
