#include "tlv/format.h"

tlv_result_t tlv_format_init(tlv_format_t* format, const void* context, tlv_read_tag_fn read_tag,
                             tlv_read_length_fn read_length, tlv_write_tag_fn write_tag,
                             tlv_write_length_fn write_length, tlv_length_size_fn length_size) {
    int has_read = read_tag || read_length;
    int has_write = write_tag || write_length || length_size;
    if (!format) return TLV_ERR_INVALID_ARG;
    if (has_read && !(read_tag && read_length)) return TLV_ERR_INVALID_ARG;
    if (has_write && !(write_tag && write_length && length_size)) return TLV_ERR_INVALID_ARG;
    if (!has_read && !has_write) return TLV_ERR_INVALID_ARG;
    *format = (tlv_format_t){.context = context,
                             .read_tag = read_tag,
                             .read_length = read_length,
                             .write_tag = write_tag,
                             .write_length = write_length,
                             .length_size = length_size};
    return TLV_OK;
}

tlv_result_t tlv_format_init_element(tlv_format_t* format, const void* context,
                                     tlv_read_element_fn read_element,
                                     tlv_write_header_fn write_header) {
    if (!format || (!read_element && !write_header)) return TLV_ERR_INVALID_ARG;
    *format = (tlv_format_t){
        .context = context, .read_element = read_element, .write_header = write_header};
    return TLV_OK;
}

int tlv_format_can_read(const tlv_format_t* format) {
    return format && (format->read_element || (format->read_tag && format->read_length));
}

int tlv_format_can_write(const tlv_format_t* format) {
    return format && (format->write_header ||
                      (format->write_tag && format->write_length && format->length_size));
}
