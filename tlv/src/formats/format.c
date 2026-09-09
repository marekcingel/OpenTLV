#include "tlv/formats/format.h"

tlv_result_t tlv_reader_format_init(tlv_reader_format_t* format, const void* context,
                                     tlv_read_tag_fn read_tag, tlv_read_length_fn read_length) {
    if (!format || !read_tag || !read_length) return TLV_ERR_INVALID_ARG;
    *format = (tlv_reader_format_t){.context = context, .read_tag = read_tag,
                                   .read_length = read_length};
    return TLV_OK;
}

tlv_result_t tlv_writer_format_init(tlv_writer_format_t* format, const void* context,
                                     tlv_write_tag_fn write_tag, tlv_write_length_fn write_length,
                                     tlv_length_size_fn length_size) {
    if (!format || !write_tag || !write_length || !length_size) return TLV_ERR_INVALID_ARG;
    *format = (tlv_writer_format_t){.context = context, .write_tag = write_tag,
                                   .write_length = write_length, .length_size = length_size};
    return TLV_OK;
}
