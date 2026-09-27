#include "common.h"
#include "tlv/formats/fixed.h"

/* Tag widths past this are not tried: wide enough to reach past every
 * built-in format's own tag limit (matching roundtrip.c's convention) while
 * keeping the selector space small. */
#define FUZZ_FIXED_MAX_TAG_SIZE 16

/* First four input bytes select a tlv_fixed_format_t configuration, masked
 * into tlv_fixed_format_init()'s valid ranges so every derived configuration
 * is accepted; the remaining bytes are the payload. This lets libFuzzer
 * discover any tag width, length width, byte order, field order and length
 * scope combination instead of only a hard-coded few, while still reusing one
 * harness. */
static tlv_fixed_format_t fuzz_fixed_config(const uint8_t* data, size_t size) {
    tlv_fixed_format_t config;
    config.tag_size = 1 + (size_t)((size > 0 ? data[0] : 0) % FUZZ_FIXED_MAX_TAG_SIZE);
    config.length_size = 1 + (size_t)((size > 1 ? data[1] : 0) % 8);
    config.length_order =
        ((size > 2 ? data[2] : 0) & 1) ? TLV_BYTE_ORDER_LITTLE_ENDIAN : TLV_BYTE_ORDER_BIG_ENDIAN;
    config.element_order =
        ((size > 3 ? data[3] : 0) & 1) ? TLV_ELEMENT_ORDER_LTV : TLV_ELEMENT_ORDER_TLV;
    config.length_scope =
        ((size > 3 ? data[3] : 0) & 2) ? TLV_LENGTH_SCOPE_TAG_AND_VALUE : TLV_LENGTH_SCOPE_VALUE;
    return config;
}

/* Splits the payload into a tag_size-byte tag and a value, writes it, and
 * reads the result back, checking exact framing overhead, insufficient
 * output capacity, and tag/value equality. Mirrors roundtrip.c's
 * check_roundtrip(), but against one derived Fixed configuration instead of
 * every enabled format, and with an exact (not bounded) overhead check since
 * both widths are known. */
static void check_fixed_roundtrip(const tlv_format_t* format, const tlv_fixed_format_t* config,
                                  const uint8_t* data, size_t size) {
    if (size < config->tag_size) return;
    tlv_tag_t      tag = tlv_tag(data, config->tag_size);
    const uint8_t* value = data + config->tag_size;
    size_t         value_size = size - config->tag_size;
    size_t         total = SIZE_MAX, written = SIZE_MAX, consumed = SIZE_MAX;
    tlv_result_t   rc = tlv_encoded_size(tag, value_size, format, &total);
    if (rc != TLV_OK) {
        FUZZ_CHECK(total == SIZE_MAX);
        return;
    }
    FUZZ_CHECK(total == config->tag_size + config->length_size + value_size);
    uint8_t* encoded = (uint8_t*)malloc(total);
    FUZZ_CHECK(encoded != NULL);
    memset(encoded, 0xa5, total);
    FUZZ_CHECK(tlv_write(encoded, total - 1, format, tag, value, value_size, &written) ==
               TLV_ERR_BUFFER_TOO_SHORT);
    FUZZ_CHECK(written == total);
    for (size_t j = 0; j < total; ++j) FUZZ_CHECK(encoded[j] == 0xa5);
    written = SIZE_MAX;
    FUZZ_CHECK(tlv_write(encoded, total, format, tag, value, value_size, &written) == TLV_OK);
    FUZZ_CHECK(written == total);
    tlv_element_t element = fuzz_sentinel(value);
    FUZZ_CHECK(tlv_read(encoded, written, format, &element, &consumed) == TLV_OK);
    FUZZ_CHECK(consumed == written);
    fuzz_element_bounds(&element, encoded, written);
    FUZZ_CHECK(element.tag.size == tag.size);
    FUZZ_CHECK(memcmp(element.tag.data, tag.data, tag.size) == 0);
    FUZZ_CHECK(element.value.size == value_size);
    if (value_size) FUZZ_CHECK(memcmp(element.value.data, value, value_size) == 0);
    free(encoded);
}

/* Feeds the same payload directly to tlv_read as raw (unconstructed) wire
 * bytes, sequentially consuming elements as far as they parse. Since the
 * payload was not built as a valid encoding of this configuration, this
 * exercises truncated tags, truncated or overrunning lengths, and truncated
 * values for the derived configuration. Mirrors reader/read.c's malformed-
 * input loop against one format instead of every enabled one. */
static void check_fixed_malformed_read(const tlv_format_t* format, const uint8_t* data,
                                       size_t size) {
    size_t pos = 0;
    do {
        tlv_element_t element = fuzz_sentinel(data), before = element;
        size_t        consumed = SIZE_MAX;
        tlv_result_t  rc = tlv_read(data + pos, size - pos, format, &element, &consumed);
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

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    size_t             prefix = size < 4 ? size : 4;
    tlv_fixed_format_t config = fuzz_fixed_config(data, size);
    tlv_format_t       format;
    FUZZ_CHECK(tlv_fixed_format_init(&format, &config) == TLV_OK);
    const uint8_t* payload = data + prefix;
    size_t         payload_size = size - prefix;
    check_fixed_roundtrip(&format, &config, payload, payload_size);
    check_fixed_malformed_read(&format, payload, payload_size);
    return 0;
}
