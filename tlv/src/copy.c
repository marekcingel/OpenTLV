#include "tlv/copy.h"
#include "tlv/writer.h"
#include <string.h>

tlv_result_t tlv_copy_encoded(tlv_buffer_t encoded, uint8_t* data,
                              size_t capacity, size_t* written) {
    if (!written || (!data && capacity) || (!encoded.data && encoded.length))
        return TLV_ERR_NULL_ARG;
    if (!data) {
        *written = encoded.length;
        return TLV_OK;
    }
    if (capacity < encoded.length) return TLV_ERR_BUFFER_TOO_SHORT;
    if (encoded.length) memmove(data, encoded.data, encoded.length);
    *written = encoded.length;
    return TLV_OK;
}

tlv_result_t tlv_copy_value(const tlv_view_t* view, uint8_t* data,
                            size_t capacity, size_t* written) {
    if (!view) return TLV_ERR_NULL_ARG;
    return tlv_copy_encoded(view->value, data, capacity, written);
}

tlv_result_t tlv_copy_view(const tlv_view_t* view, const tlv_format_t* format,
                           uint8_t* data, size_t capacity, size_t* written) {
    if (!view || !written || (!data && capacity) ||
        (!view->value.data && view->value.length)) return TLV_ERR_NULL_ARG;
    if (!data)
        return tlv_encoded_size(view->tag, view->value.length, format, written);
    return tlv_write(data, capacity, format, view->tag, view->value.data,
                     view->value.length, written);
}
