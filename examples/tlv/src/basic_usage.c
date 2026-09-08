#include "tlv/formats/default.h"
#include "tlv/formats/fixed_1byte.h"
#include "tlv/formats/ber.h"
/* C API tour: all storage belongs to the caller; no heap allocation. */
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include "tlv/copy.h"
#include "tlv/codec/codec.h"
#include "tlv/endian.h"
#include "tlv/reader/reader.h"
#include "tlv/reader/scanner.h"
#include "tlv/schemas/schema.h"
#include "tlv/version.h"
#include "tlv/reader/walker.h"
#include "tlv/writer/writer.h"

#define CHECK(call) do { \
    tlv_result_t rc_ = (call); \
    if (rc_ != TLV_OK) { \
        fprintf(stderr, "%s: %s\n", #call, tlv_strerror(rc_)); return 1; \
    } \
} while (0)
#define CHECK_CODEC(call) do { \
    tlv_codec_result_t rc_ = (call); \
    if (rc_ != TLV_CODEC_OK) { \
        fprintf(stderr, "%s: %s\n", #call, tlv_codec_strerror(rc_)); return 1; \
    } \
} while (0)

static void print_view(const tlv_view_t* view) {
    size_t i;
    printf("tag=");
    for (i = 0; i < view->tag.size; ++i) printf("%02X", (unsigned)view->tag.data[i]);
    printf(" length=%zu value=", view->value.length);
    for (i = 0; i < view->value.length; ++i) printf("%02X ", (unsigned)view->value.data[i]);
    putchar('\n');
}

static int sequential_io(void) {
    uint8_t buffer[64];
    tlv_writer_t writer;
    tlv_reader_t reader;
    tlv_view_t view;
    puts("\nSequential writer and zero-copy reader (default format)");
    CHECK(tlv_writer_init(&writer, buffer, sizeof(buffer), &tlv_format_default));
    CHECK(tlv_writer_write(&writer, (tlv_tag_t){{1}, 1}, (const uint8_t*)"hello", 5));
    CHECK(tlv_writer_write(&writer, (tlv_tag_t){{2}, 1}, (const uint8_t*)"world", 5));
    printf("Wrote %zu bytes\n", tlv_writer_size(&writer));
    CHECK(tlv_reader_init(&reader, buffer, tlv_writer_size(&writer), &tlv_format_default));
    while (!tlv_reader_at_end(&reader)) {
        CHECK(tlv_reader_next(&reader, &view));
        /* view.value borrows buffer; keep buffer alive while using the view. */
        print_view(&view);
    }
    return 0;
}

static int single_element_and_copies(void) {
    uint8_t input[32], owned[8], exact[32], serialized[32];
    const uint8_t value[] = {0xAB, 0xCD};
    const tlv_tag_t tag = {{0x42}, 1};
    tlv_view_t view;
    size_t required, encoded_size, consumed, written;
    tlv_result_t result;
    puts("\nSingle-element I/O and explicit copies (fixed 1-byte format)");
    CHECK(tlv_encoded_size(tag, sizeof(value), &tlv_format_fixed_1byte, &required));
    printf("Required encoded storage: %zu bytes\n", required);
    CHECK(tlv_write(input, sizeof(input), &tlv_format_fixed_1byte,
                    tag, value, sizeof(value), &encoded_size));
    CHECK(tlv_read(input, encoded_size, &tlv_format_fixed_1byte, &view, &consumed));
    CHECK(tlv_copy_value(&view, NULL, 0, &required));
    printf("Required value storage: %zu bytes\n", required);
    result = tlv_copy_value(&view, owned, 1, &written);
    if (result != TLV_ERR_BUFFER_TOO_SHORT) return 1;
    printf("Expected capacity error: %s\n", tlv_strerror(result));
    CHECK(tlv_copy_value(&view, owned, sizeof(owned), &written));
    CHECK(tlv_copy_encoded((tlv_buffer_t){input, consumed}, NULL, 0, &required));
    printf("Required exact-copy storage: %zu bytes\n", required);
    CHECK(tlv_copy_encoded((tlv_buffer_t){input, consumed}, exact, sizeof(exact), &written));
    /* A view does not retain the original header. Serialization may normalize
     * it (e.g. BER lengths); copy_encoded preserves the original bytes. */
    CHECK(tlv_copy_view(&view, &tlv_format_fixed_1byte, NULL, 0, &required));
    printf("Required serialized-view storage: %zu bytes\n", required);
    CHECK(tlv_copy_view(&view, &tlv_format_fixed_1byte, serialized, sizeof(serialized), &written));
    /* Keep the inline tag; redirect the value to caller-owned storage. */
    view.value.data = owned;
    memset(input, 0, sizeof(input));
    puts("Value after reusing input:");
    print_view(&view);
    CHECK(tlv_read(exact, consumed, &tlv_format_fixed_1byte, &view, &written));
    puts("Exact encoded copy after reusing input:");
    print_view(&view);
    return 0;
}

static int ber_format(void) {
#if TLV_TAG_MAX_SIZE >= 2
    const tlv_tag_t tag = {{0x9F, 0x1C}, 2};
#else
    const tlv_tag_t tag = {{0x5A}, 1};
#endif
    uint8_t value[128] = {0}, encoded[144];
    size_t required, written, consumed;
    tlv_view_t view;
    puts("\nBER: multi-byte tag when supported, long-form length");
    CHECK(tlv_encoded_size(tag, sizeof(value), &tlv_format_ber, &required));
    CHECK(tlv_write(encoded, sizeof(encoded), &tlv_format_ber, tag, value, sizeof(value), &written));
    CHECK(tlv_read(encoded, written, &tlv_format_ber, &view, &consumed));
    printf("Tag bytes: %u, value bytes: %zu, encoded bytes: %zu\n",
           (unsigned)view.tag.size, view.value.length, required);
    return 0;
}

static const tlv_schema_entry_t schema_entries[] = {
    {{{1}, 1}, 2, 2, 0}, /* Exact length. */
    {{{2}, 1}, 0, 4, 0}  /* Inclusive length range. */
};
static const tlv_schema_t schema = {
    schema_entries, sizeof(schema_entries) / sizeof(schema_entries[0])
};
typedef struct { size_t count; size_t stop_after; } visit_context_t;

static tlv_visit_result_t visit(const tlv_view_t* view, void* context) {
    visit_context_t* state = (visit_context_t*)context;
    const tlv_schema_entry_t* entry = tlv_schema_find(&schema, &view->tag);
    if (!entry || tlv_schema_validate_length(entry, view->value.length) != TLV_OK)
        return TLV_VISIT_ERROR;
    print_view(view); /* The view pointer is valid only during this callback. */
    ++state->count;
    return state->stop_after && state->count >= state->stop_after
        ? TLV_VISIT_STOP : TLV_VISIT_CONTINUE;
}

static int schema_walk_and_scan(void) {
    const uint8_t input[] = {1, 2, 0xAB, 0xCD, 2, 0};
    const uint8_t noisy[] = {0xFF, 0xFF, 1, 2, 0xAB, 0xCD};
    const uint8_t invalid[] = {1, 0}; /* Valid framing, invalid schema length. */
    tlv_view_t view;
    size_t offset, consumed;
    tlv_result_t result;
    visit_context_t state = {0, 0};
    puts("\nSchema validation in a walker callback");
    CHECK(tlv_walk(input, sizeof(input), &tlv_format_fixed_1byte, visit, &state));
    printf("Visited %zu elements\n", state.count);
    state.count = 0;
    state.stop_after = 1;
    CHECK(tlv_walk(input, sizeof(input), &tlv_format_fixed_1byte, visit, &state));
    printf("Stopped successfully after %zu element\n", state.count);
    /* Parsing never applies a schema automatically; our callback does. */
    result = tlv_walk(invalid, sizeof(invalid), &tlv_format_fixed_1byte, visit, &state);
    if (result != TLV_ERR_VISITOR) return 1;
    printf("Schema rejection by visitor: %s\n", tlv_strerror(result));
    puts("Recovery scan with a schema filter");
    CHECK(tlv_scan(noisy, sizeof(noisy), 0, &tlv_format_fixed_1byte,
                   &schema, &view, &offset, &consumed));
    printf("Candidate at offset %zu, encoded size %zu\n", offset, consumed);
    print_view(&view);
    /* A candidate is not proof of an original boundary. Continue after it. */
    result = tlv_scan(noisy, sizeof(noisy), offset + consumed, &tlv_format_fixed_1byte,
                      &schema, &view, &offset, &consumed);
    if (result != TLV_ERR_END_OF_BUFFER) return 1;
    printf("No further candidate: %s\n", tlv_strerror(result));
    return 0;
}

/* Application codec: an aligned uint32_t C object <-> four big-endian bytes.
 * Generic wrappers validate pointers; callbacks validate sizes/capacities. */
static tlv_codec_result_t decode_u32(const void* context, const uint8_t* data,
                                    size_t size, void* value, size_t capacity) {
    (void)context;
    if (size != 4) return TLV_CODEC_ERR_INVALID_VALUE;
    if (capacity < sizeof(uint32_t)) return TLV_CODEC_ERR_BUFFER_TOO_SHORT;
    *(uint32_t*)value = tlv_read_u32_be(data);
    return TLV_CODEC_OK;
}
static tlv_codec_result_t encode_u32(const void* context, const void* value,
                                    size_t size, uint8_t* data, size_t capacity,
                                    size_t* written) {
    (void)context;
    if (size != sizeof(uint32_t)) return TLV_CODEC_ERR_INVALID_VALUE;
    if (!data) { *written = 4; return TLV_CODEC_OK; }
    if (capacity < 4) return TLV_CODEC_ERR_BUFFER_TOO_SHORT;
    tlv_write_u32_be(data, *(const uint32_t*)value);
    *written = 4;
    return TLV_CODEC_OK;
}

static int codecs_and_endian(void) {
    const tlv_codec_t codec = {NULL, decode_u32, encode_u32};
    const uint32_t number = UINT32_C(0x12345678);
    uint32_t decoded;
    uint8_t raw[4], encoded[16];
    size_t required, written, encoded_size, consumed;
    tlv_view_t view;
    puts("\nExplicit value codec inside TLV framing");
    CHECK_CODEC(tlv_codec_encode(&codec, &number, sizeof(number), NULL, 0, &required));
    printf("Codec needs %zu bytes\n", required);
    CHECK_CODEC(tlv_codec_encode(&codec, &number, sizeof(number), raw, sizeof(raw), &written));
    CHECK(tlv_write(encoded, sizeof(encoded), &tlv_format_fixed_1byte,
                    (tlv_tag_t){{3}, 1}, raw, written, &encoded_size));
    CHECK(tlv_read(encoded, encoded_size, &tlv_format_fixed_1byte, &view, &consumed));
    CHECK_CODEC(tlv_codec_decode(&codec, view.value.data, view.value.length, &decoded, sizeof(decoded)));
    printf("Decoded uint32 BE: 0x%08" PRIX32 "\n", decoded);
    /* Endian helpers are also usable directly. They do not check bounds:
     * raw has four bytes, enough for every call below. */
    tlv_write_u16_be(raw, UINT16_C(0x1234));
    printf("uint16 BE: 0x%04X\n", (unsigned)tlv_read_u16_be(raw));
    tlv_write_u16_le(raw, UINT16_C(0x1234));
    printf("uint16 LE: 0x%04X\n", (unsigned)tlv_read_u16_le(raw));
    tlv_write_u32_le(raw, number);
    printf("uint32 LE: 0x%08" PRIX32 "\n", tlv_read_u32_le(raw));
    return 0;
}

/* Custom profile: reuse fixed-format tag callbacks, replace the length with
 * a two-byte little-endian field. Callbacks also support writer size queries. */
static tlv_result_t read_length_le16(const void* context, const uint8_t* data,
                                    size_t size, size_t* length, size_t* consumed) {
    (void)context;
    if (size < 2) return TLV_ERR_BUFFER_TOO_SHORT;
    *length = tlv_read_u16_le(data);
    *consumed = 2;
    return TLV_OK;
}
static tlv_result_t length_size_le16(const void* context, size_t length, size_t* size) {
    (void)context;
    if (length > UINT16_MAX) return TLV_ERR_INVALID_LENGTH;
    *size = 2;
    return TLV_OK;
}
static tlv_result_t write_length_le16(const void* context, uint8_t* data,
                                     size_t capacity, size_t length, size_t* written) {
    size_t required;
    tlv_result_t result = length_size_le16(context, length, &required);
    if (result != TLV_OK) return result;
    if (capacity < required) return TLV_ERR_BUFFER_TOO_SHORT;
    tlv_write_u16_le(data, (uint16_t)length);
    *written = required;
    return TLV_OK;
}
static int custom_format(void) {
    tlv_format_t format = tlv_format_fixed_1byte;
    uint8_t encoded[16];
    const uint8_t value[] = {0xAA};
    tlv_view_t view;
    size_t written, consumed;
    format.read_length = read_length_le16;
    format.write_length = write_length_le16;
    format.length_size = length_size_le16;
    /* format and its optional immutable context must outlive their users. */
    puts("\nCustom format: one-byte tag, two-byte little-endian length");
    CHECK(tlv_write(encoded, sizeof(encoded), &format,
                    (tlv_tag_t){{1}, 1}, value, sizeof(value), &written));
    CHECK(tlv_read(encoded, written, &format, &view, &consumed));
    print_view(&view);
    return 0;
}

int main(void) {
    printf("OpenTLV headers: %s; runtime: %s\n", OPENTLV_VERSION_STRING, tlv_version_string());
    printf("Runtime source: %s, branch %s, commit %s\n",
           tlv_version_git_repo(), tlv_version_git_branch(), tlv_version_git_commit_hash());
    if (sequential_io() || single_element_and_copies() || ber_format() ||
        schema_walk_and_scan() || codecs_and_endian() || custom_format()) return 1;
    return 0;
}
