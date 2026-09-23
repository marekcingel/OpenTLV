/*
 * An application codec (an aligned uint32_t C object <-> four big-endian
 * bytes) used inside TLV framing, and the standalone endian helpers.
 * Generic wrappers validate pointers; callbacks validate sizes/capacities.
 */
#include <inttypes.h>
#include <stdio.h>
#include "tlv/builtins/fixed/fixed_1byte.h"
#include "tlv/codec/codec.h"
#include "tlv/endian.h"
#include "tlv/length.h"
#include "tlv/reader/reader.h"
#include "tlv/writer/writer.h"

#define CHECK(call)                                                                                \
    do {                                                                                           \
        tlv_result_t rc_ = (call);                                                                 \
        if (rc_ != TLV_OK) {                                                                       \
            fprintf(stderr, "%s: %s\n", #call, tlv_strerror(rc_));                                 \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)
#define CHECK_CODEC(call)                                                                          \
    do {                                                                                           \
        tlv_codec_result_t rc_ = (call);                                                           \
        if (rc_ != TLV_CODEC_OK) {                                                                 \
            fprintf(stderr, "%s: %s\n", #call, tlv_codec_strerror(rc_));                           \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

static tlv_codec_result_t decode_u32(const void* context, const uint8_t* data, size_t size,
                                     void* value, size_t capacity) {
    (void)context;
    if (size != sizeof(uint32_t)) return TLV_CODEC_ERR_INVALID_VALUE;
    if (capacity < sizeof(uint32_t)) return TLV_CODEC_ERR_BUFFER_TOO_SHORT;
    *(uint32_t*)value = tlv_read_u32_be(data);
    return TLV_CODEC_OK;
}
static tlv_codec_result_t encode_u32(const void* context, const void* value, size_t size,
                                     uint8_t* data, size_t capacity, size_t* written) {
    (void)context;
    if (size != sizeof(uint32_t)) return TLV_CODEC_ERR_INVALID_VALUE;
    if (!data) {
        *written = sizeof(uint32_t);
        return TLV_CODEC_OK;
    }
    if (capacity < sizeof(uint32_t)) return TLV_CODEC_ERR_BUFFER_TOO_SHORT;
    tlv_write_u32_be(data, *(const uint32_t*)value);
    *written = sizeof(uint32_t);
    return TLV_CODEC_OK;
}

int main(void) {
    const tlv_codec_t codec = {NULL, decode_u32, encode_u32};
    const uint32_t    number = UINT32_C(0x12345678);
    uint32_t          decoded;
    uint8_t           raw[sizeof(uint32_t)], encoded[16];
    size_t            required, written, encoded_size, consumed;
    tlv_view_t        view;

    CHECK_CODEC(tlv_codec_encode(&codec, &number, sizeof(number), NULL, 0, &required));
    printf("Codec needs %zu bytes\n", required);
    CHECK_CODEC(tlv_codec_encode(&codec, &number, sizeof(number), raw, sizeof(raw), &written));
    CHECK(tlv_write(encoded, sizeof(encoded), &tlv_writer_format_fixed_1byte, TLV_TAG(3), raw,
                    written, &encoded_size));
    CHECK(tlv_read(encoded, encoded_size, &tlv_reader_format_fixed_1byte, &view, &consumed));
    {
        size_t value_length;
        CHECK(tlv_length_to_size(view.value.length, &value_length));
        CHECK_CODEC(
            tlv_codec_decode(&codec, view.value.data, value_length, &decoded, sizeof(decoded)));
    }
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
