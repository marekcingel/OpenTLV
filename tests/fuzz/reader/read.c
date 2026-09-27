#include "formats.h"

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    for (size_t i = 0; fuzz_formats[i].format; ++i) {
        size_t pos = 0;
        /* Include an empty read after the last element. */
        do {
            tlv_element_t element = fuzz_sentinel(data), before = element;
            size_t        consumed = SIZE_MAX;
            tlv_result_t  rc =
                tlv_read(data + pos, size - pos, fuzz_formats[i].format, &element, &consumed);
            if (rc != TLV_OK) {
                fuzz_unchanged(&element, &before);
                FUZZ_CHECK(consumed == SIZE_MAX);
                break;
            }
            FUZZ_CHECK(consumed > 0 && consumed <= size - pos);
            fuzz_element_bounds(&element, data + pos, consumed);
            pos += consumed;
        } while (pos <= size);
    }
    return 0;
}
