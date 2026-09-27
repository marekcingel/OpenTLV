#include <string.h>
#include "tlv/formats/fixed.h"
#include "tlv/reader/reader.h"
#include "tlv/writer/writer.h"

int main(void) {
    /* One tag byte and one length byte; config must outlive its readers and writers. */
    const tlv_fixed_format_t config = {
        .tag_size = 1, .length_size = 1, .length_order = TLV_BYTE_ORDER_BIG_ENDIAN};
    tlv_format_t format;
    if (tlv_fixed_format_init(&format, &config) != TLV_OK) return 1;

    const tlv_tag_t tag = TLV_TAG(0x01);
    const uint8_t   value[] = {0xAA, 0xBB, 0xCC};
    uint8_t         buffer[5];
    size_t          written = 0, consumed = 0;
    tlv_element_t   element;

    if (tlv_write(buffer, sizeof(buffer), &format, tag, value, sizeof(value), &written) != TLV_OK)
        return 1;
    if (tlv_read(buffer, written, &format, &element, &consumed) != TLV_OK) return 1;

    /* element.value borrows buffer; keep it alive while using the element. */
    if (consumed != written || element.tag.size != 1 || element.tag.data[0] != 0x01) return 1;
    if (element.value.size != sizeof(value) ||
        memcmp(element.value.data, value, sizeof(value)) != 0)
        return 1;
    return 0;
}
