#include "tlv/formats/asn1/ber.h"
#include "ber_internal.h"
static tlv_result_t read_tag(const void* context, const uint8_t* data, size_t size, tlv_tag_t* tag, size_t* used) {
    return tlv_ber_reader_wire.read_tag(context, data, size, tag, used);
}
static tlv_result_t write_tag(const void* context, uint8_t* data, size_t capacity, const tlv_tag_t* tag, size_t* used) {
    return tlv_ber_writer_wire.write_tag(context, data, capacity, tag, used);
}
static tlv_result_t read_length(const void* context, const uint8_t* data, size_t size, size_t* length, size_t* used) {
    return tlv_ber_reader_wire.read_length(context, data, size, length, used);
}
static tlv_result_t write_length(const void* context, uint8_t* data, size_t capacity, size_t length, size_t* used) {
    return tlv_ber_writer_wire.write_length(context, data, capacity, length, used);
}
static tlv_result_t length_size(const void* context, size_t length, size_t* size) {
    return tlv_ber_writer_wire.length_size(context, length, size);
}
int tlv_ber_is_constructed(const void* context, const tlv_tag_t* tag) {
    (void)context;
    return (tag->data[0] & 0x20) != 0;
}
const tlv_reader_format_t tlv_reader_format_ber = {
    .context = NULL,
    .read_tag = read_tag,
    .read_length = read_length
};

const tlv_writer_format_t tlv_writer_format_ber = {
    .context = NULL,
    .write_tag = write_tag,
    .write_length = write_length,
    .length_size = length_size
};
