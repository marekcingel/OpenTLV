#include <string.h>
#include "tlv/builtins/fixed/fixed.h"
#include "tlv/reader/reader.h"
#include "tlv/writer/writer.h"

int main(void) {
    /* One tag byte and one length byte; config must outlive its readers and writers. */
    const tlv_fixed_config_t config = {
        .tag_size = 1, .length_size = 1, .order = TLV_BYTE_ORDER_BIG_ENDIAN};
    tlv_reader_format_t reader_format;
    tlv_writer_format_t writer_format;
    if (tlv_fixed_reader_format_init(&reader_format, &config) != TLV_OK) return 1;
    if (tlv_fixed_writer_format_init(&writer_format, &config) != TLV_OK) return 1;

    const tlv_tag_t tag = TLV_TAG(0x01);
    const uint8_t   value[] = {0xAA, 0xBB, 0xCC};
    uint8_t         buffer[5];
    size_t          written = 0, consumed = 0;
    tlv_view_t      view;

    if (tlv_write(buffer, sizeof(buffer), &writer_format, tag, value, sizeof(value), &written) !=
        TLV_OK)
        return 1;
    if (tlv_read(buffer, written, &reader_format, &view, &consumed) != TLV_OK) return 1;

    /* view.value borrows buffer; keep it alive while using the view. */
    if (consumed != written || view.tag.size != 1 || view.tag.data[0] != 0x01) return 1;
    if (view.value.length != sizeof(value) || memcmp(view.value.data, value, sizeof(value)) != 0)
        return 1;
    return 0;
}
