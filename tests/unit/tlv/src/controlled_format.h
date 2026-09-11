#ifndef OPENTLV_TEST_CONTROLLED_FORMAT_H
#define OPENTLV_TEST_CONTROLLED_FORMAT_H

#include "tlv/formats/format.h"

// Small callbacks for generic component contracts, independent of optional formats.
namespace controlled {
inline tlv_result_t read_tag(const void*, const uint8_t* data, size_t size,
                             tlv_tag_t* tag, size_t* used) {
    if (!size) return TLV_ERR_BUFFER_TOO_SHORT;
    *tag = tlv_tag_t{{data[0]}, 1};
    *used = 1;
    return TLV_OK;
}
inline tlv_result_t read_length(const void*, const uint8_t* data, size_t size,
                                size_t* length, size_t* used) {
    if (!size) return TLV_ERR_BUFFER_TOO_SHORT;
    *length = data[0];
    *used = 1;
    return TLV_OK;
}
inline tlv_result_t write_tag(const void*, uint8_t* data, size_t size,
                              const tlv_tag_t* tag, size_t* used) {
    if (tag->size != 1) return TLV_ERR_INVALID_TAG;
    if (data && !size) return TLV_ERR_BUFFER_TOO_SHORT;
    if (data) data[0] = tag->data[0];
    *used = 1;
    return TLV_OK;
}
inline tlv_result_t length_size(const void*, size_t length, size_t* used) {
    if (length > 255) return TLV_ERR_INVALID_LENGTH;
    *used = 1;
    return TLV_OK;
}
inline tlv_result_t write_length(const void* context, uint8_t* data, size_t size,
                                 size_t length, size_t* used) {
    const auto result = length_size(context, length, used);
    if (result != TLV_OK) return result;
    if (!size) return TLV_ERR_BUFFER_TOO_SHORT;
    data[0] = static_cast<uint8_t>(length);
    return TLV_OK;
}
const tlv_reader_format_t reader = {nullptr, read_tag, read_length, nullptr};
const tlv_writer_format_t writer = {nullptr, write_tag, write_length, length_size};
}

#endif
