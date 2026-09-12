#include "formats.h"

static void check_roundtrip(size_t format, tlv_tag_t tag,
                            const uint8_t* value, size_t length) {
    size_t total = SIZE_MAX, written = SIZE_MAX, consumed = SIZE_MAX;
    tlv_result_t rc = tlv_encoded_size(tag, length, fuzz_formats[format].writer, &total);
    if (rc != TLV_OK) {
        FUZZ_CHECK(total == SIZE_MAX);
        return;
    }
    FUZZ_CHECK(total >= length && total - length <= TLV_TAG_MAX_SIZE + sizeof(size_t) + 2);
    FUZZ_CHECK(total > 0);
    uint8_t* encoded = (uint8_t*)malloc(total);
    FUZZ_CHECK(encoded != NULL);
    memset(encoded, 0xa5, total);
    FUZZ_CHECK(tlv_write(encoded, total - 1, fuzz_formats[format].writer,
        tag, value, length, &written) != TLV_OK);
    FUZZ_CHECK(written == SIZE_MAX);
    for (size_t j = 0; j < total; ++j) FUZZ_CHECK(encoded[j] == 0xa5);
    FUZZ_CHECK(tlv_write(encoded, total, fuzz_formats[format].writer,
        tag, value, length, &written) == TLV_OK);
    FUZZ_CHECK(written == total);
    tlv_view_t view = fuzz_sentinel(value);
    FUZZ_CHECK(tlv_read(encoded, written, fuzz_formats[format].reader,
        &view, &consumed) == TLV_OK);
    FUZZ_CHECK(consumed == written);
    fuzz_view_bounds(&view, encoded, written);
    FUZZ_CHECK(view.tag.size == tag.size);
    FUZZ_CHECK(memcmp(view.tag.data, tag.data, tag.size) == 0);
    FUZZ_CHECK(view.value.length == length);
    if (length) FUZZ_CHECK(memcmp(view.value.data, value, length) == 0);
    free(encoded);
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    tlv_tag_t tag = {{0}, 0};
    size_t tag_size = size ? data[0] % (TLV_TAG_MAX_SIZE + 1) : 0;
    if (size && tag_size > size - 1) tag_size = size - 1;
    tag.size = (uint8_t)tag_size;
    if (tag_size) memcpy(tag.data, data + 1, tag_size);
    size_t prefix = size ? 1 + tag_size : 0;
    for (size_t i = 0; fuzz_formats[i].reader; ++i) {
        check_roundtrip(i, tag, data + prefix, size - prefix);
        /* Always exercise successful writes, even when the random tag is invalid. */
        tlv_tag_t primitive = {{0x04}, 1};
        check_roundtrip(i, primitive, data, size);
    }
    return 0;
}
