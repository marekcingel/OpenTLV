#include "formats.h"

/* Candidate tags up to this size are tried, which reaches past the longest tag any format accepts.
 */
#define FUZZ_MAX_TAG_SIZE 16

static void check_roundtrip(size_t format, tlv_tag_t tag, const uint8_t* value, size_t length) {
    size_t       total = SIZE_MAX, written = SIZE_MAX, consumed = SIZE_MAX;
    tlv_result_t rc = tlv_encoded_size(tag, length, fuzz_formats[format].writer, &total);
    if (rc != TLV_OK) {
        FUZZ_CHECK(total == SIZE_MAX);
        return;
    }
    FUZZ_CHECK(total >= length && total - length <= FUZZ_MAX_TAG_SIZE + sizeof(size_t) + 2);
    FUZZ_CHECK(total > 0);
    uint8_t* encoded = (uint8_t*)malloc(total);
    FUZZ_CHECK(encoded != NULL);
    memset(encoded, 0xa5, total);
    FUZZ_CHECK(tlv_write(encoded, total - 1, fuzz_formats[format].writer, tag, value, length,
                         &written) == TLV_ERR_BUFFER_TOO_SHORT);
    FUZZ_CHECK(written == total);
    for (size_t j = 0; j < total; ++j) FUZZ_CHECK(encoded[j] == 0xa5);
    written = SIZE_MAX;
    FUZZ_CHECK(tlv_write(encoded, total, fuzz_formats[format].writer, tag, value, length,
                         &written) == TLV_OK);
    FUZZ_CHECK(written == total);
    tlv_view_t view = fuzz_sentinel(value);
    FUZZ_CHECK(tlv_read(encoded, written, fuzz_formats[format].reader, &view, &consumed) == TLV_OK);
    FUZZ_CHECK(consumed == written);
    fuzz_view_bounds(&view, encoded, written);
    FUZZ_CHECK(view.tag.size == tag.size);
    FUZZ_CHECK(memcmp(view.tag.data, tag.data, tag.size) == 0);
    FUZZ_CHECK(view.value.length == length);
    if (length) FUZZ_CHECK(memcmp(view.value.data, value, length) == 0);
    free(encoded);
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    size_t tag_size = size ? data[0] % (FUZZ_MAX_TAG_SIZE + 1) : 0;
    if (size && tag_size > size - 1) tag_size = size - 1;
    tlv_tag_t tag = tag_size ? tlv_tag(data + 1, tag_size) : tlv_tag(NULL, 0);
    size_t    prefix = size ? 1 + tag_size : 0;
    for (size_t i = 0; fuzz_formats[i].reader; ++i) {
        check_roundtrip(i, tag, data + prefix, size - prefix);
        /* Always exercise successful writes, even when the random tag is invalid. */
        tlv_tag_t primitive = TLV_TAG(0x04);
        check_roundtrip(i, primitive, data, size);
    }
    return 0;
}
