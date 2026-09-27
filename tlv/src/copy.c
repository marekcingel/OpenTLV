#include "tlv/copy.h"
#include "tlv/writer/writer.h"
#include "tlv/size.h"
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

tlv_result_t tlv_copy_value(const tlv_element_t* element, uint8_t* data, size_t capacity,
                            size_t* written) {
    if (!element) return TLV_ERR_NULL_ARG;
    return tlv_value_copy(element->value, data, capacity, written);
}

tlv_result_t tlv_copy_element(const tlv_element_t* element, const tlv_format_t* format,
                              uint8_t* data, size_t capacity, size_t* written) {
    size_t length, local_written;
    tlv_result_t rc;
    if (!element || !written || (!data && capacity) ||
        (!element->value.data && element->value.size))
        return TLV_ERR_NULL_ARG;
    rc = tlv_size_to_native(element->value.size, &length);
    if (rc != TLV_OK) return rc;
    if (!data) return tlv_encoded_size(element->tag, length, format, written);
    rc = tlv_write(data, capacity, format, element->tag, element->value.data, length,
                   &local_written);
    if (rc == TLV_OK) *written = local_written;
    return rc;
}
