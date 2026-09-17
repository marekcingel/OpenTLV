#include "tlv/copy.h"
#include "tlv/writer/writer.h"
#include "tlv/length.h"
#include <string.h>

tlv_result_t tlv_copy_encoded(const uint8_t* encoded_data, size_t encoded_length, uint8_t* data,
                              size_t capacity, size_t* written) {
    if (!written || (!data && capacity) || (!encoded_data && encoded_length))
        return TLV_ERR_NULL_ARG;
    if (!data) {
        *written = encoded_length;
        return TLV_OK;
    }
    if (capacity < encoded_length) return TLV_ERR_BUFFER_TOO_SHORT;
    if (encoded_length) memmove(data, encoded_data, encoded_length);
    *written = encoded_length;
    return TLV_OK;
}

tlv_result_t tlv_copy_value(const tlv_view_t* view, uint8_t* data, size_t capacity,
                            size_t* written) {
    size_t length;
    tlv_result_t rc;
    if (!view) return TLV_ERR_NULL_ARG;
    rc = tlv_length_to_size(view->value.length, &length);
    if (rc != TLV_OK) return rc;
    return tlv_copy_encoded(view->value.data, length, data, capacity, written);
}

tlv_result_t tlv_copy_view(const tlv_view_t* view, const tlv_writer_format_t* format, uint8_t* data,
                           size_t capacity, size_t* written) {
    size_t length, local_written;
    tlv_result_t rc;
    if (!view || !written || (!data && capacity) || (!view->value.data && view->value.length))
        return TLV_ERR_NULL_ARG;
    rc = tlv_length_to_size(view->value.length, &length);
    if (rc != TLV_OK) return rc;
    if (!data) return tlv_encoded_size(view->tag, length, format, written);
    rc = tlv_write(data, capacity, format, view->tag, view->value.data, length, &local_written);
    if (rc == TLV_OK) *written = local_written;
    return rc;
}
