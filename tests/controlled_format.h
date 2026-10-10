// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv/formats/compose.h"
#ifndef OPENTLV_TEST_CONTROLLED_FORMAT_H
#define OPENTLV_TEST_CONTROLLED_FORMAT_H

#include "tlv/format.h"

// Small callbacks for generic component contracts, independent of optional formats.
namespace controlled {
inline tlv_result_t read_tag(const void*, const uint8_t* data, size_t size, tlv_tag_t* tag,
                             size_t* used) {
    if (!size) return TLV_ERR_TRUNCATED;
    *tag = tlv_tag(data, 1);
    *used = 1;
    return TLV_OK;
}
inline tlv_result_t read_length(const void*, const uint8_t* data, size_t size, tlv_size_t* length,
                                size_t* used) {
    if (!size) return TLV_ERR_TRUNCATED;
    *length = data[0];
    *used = 1;
    return TLV_OK;
}
inline tlv_result_t write_tag(const void*, const tlv_tag_t* tag, uint8_t* data, size_t size,
                              size_t* used) {
    if (tag->size != 1) return TLV_ERR_INVALID_TAG_SIZE;
    if (data && !size) return TLV_ERR_BUFFER_TOO_SHORT;
    if (data) data[0] = tag->data[0];
    *used = 1;
    return TLV_OK;
}
inline tlv_result_t length_size(const void*, tlv_size_t length, size_t* used) {
    if (length > 255) return TLV_ERR_INVALID_LENGTH;
    *used = 1;
    return TLV_OK;
}
inline tlv_result_t write_length(const void* context, tlv_size_t length, uint8_t* data, size_t size,
                                 size_t* used) {
    const auto result = length_size(context, length, used);
    if (result != TLV_OK) return result;
    if (!data) return TLV_OK;
    if (!size) return TLV_ERR_BUFFER_TOO_SHORT;
    data[0] = static_cast<uint8_t>(length);
    return TLV_OK;
}
const tlv_field_composition_t format_layout = {
    nullptr,   read_tag,     read_length,           nullptr,
    write_tag, write_length, TLV_ELEMENT_ORDER_TLV, TLV_LENGTH_SCOPE_VALUE};
const tlv_format_t format = {&format_layout, tlv_fields_decode, tlv_fields_measure,
                             tlv_fields_encode, nullptr};
} // namespace controlled

#endif
