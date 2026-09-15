#include <string.h>

#include "tlv/formats/fixed/fixed_1byte.h"
#include "tlv/reader/reader.h"
#include "tlv/writer/writer.h"

int main(void) {
    const tlv_tag_t tag = {{0x01}, 1};
    const uint8_t value[] = {0xAA, 0xBB, 0xCC};
    uint8_t buffer[5];
    size_t written = 0, consumed = 0;
    tlv_view_t view;

    if (tlv_write(buffer, sizeof(buffer), &tlv_writer_format_fixed_1byte,
                  tag, value, sizeof(value), &written) != TLV_OK)
        return 1;
    if (tlv_read(buffer, written, &tlv_reader_format_fixed_1byte,
                 &view, &consumed) != TLV_OK)
        return 1;

    return consumed == written && view.tag.size == 1 &&
           view.tag.data[0] == 0x01 && view.value.length == sizeof(value) &&
           memcmp(view.value.data, value, sizeof(value)) == 0 ? 0 : 1;
}
