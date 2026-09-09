#ifndef OPENTLV_CODEC_STRUCTURE_H
#define OPENTLV_CODEC_STRUCTURE_H
#include "tlv/codec/codec.h"
#include "tlv/schemas/schema.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Object bindings belong to the codec layer. This descriptor maps a complete
 * sequence (including nested elements) to one caller-owned application object.
 * Reader format, writer format, schema and context are borrowed. Callbacks
 * follow tlv_codec_t's alignment, ownership, capacity, overlap and error
 * contracts and receive their direction's format explicitly. No tag is
 * prescribed for the complete object.
 * Decode validates the entire structure before invoking the callback. Encode
 * validates produced bytes before success; a NULL/0 size query relies on the
 * callback to validate the object without producing bytes. On any error the
 * destination is unspecified and written is zero. Callbacks must be stable
 * across sizing and writing and must consume/produce the complete sequence.
 * schema may be NULL for framing/nesting validation only. Depth and element
 * limits use tlv_walk_tree conventions; zero is a real limit. An out-of-range
 * max_depth returns TLV_CODEC_ERR_INVALID_VALUE.
 * reader_format is required for decode and for validation of encoded bytes.
 * writer_format is required only for encode; decode-only codecs may use NULL.
 * The two formats must describe the same wire encoding for encode validation.
 * is_constructed is optional and receives reader_format->context; NULL makes
 * values opaque. The codec context is passed to object callbacks only. */
typedef struct tlv_structure_codec {
    const void* context;
    const tlv_reader_format_t* reader_format;
    const tlv_writer_format_t* writer_format;
    tlv_is_constructed_fn is_constructed;
    const tlv_structure_schema_t* schema;
    size_t max_depth;
    size_t max_elements;
    tlv_codec_result_t (*decode)(const void* context, const tlv_reader_format_t* format,
                                const uint8_t* data, size_t size,
                                void* value, size_t capacity);
    tlv_codec_result_t (*encode)(const void* context, const tlv_writer_format_t* format,
                                const void* value, size_t size,
                                uint8_t* data, size_t capacity, size_t* written);
} tlv_structure_codec_t;

tlv_codec_result_t tlv_structure_decode(const tlv_structure_codec_t* codec,
                                        const uint8_t* data, size_t size,
                                        void* value, size_t capacity);
tlv_codec_result_t tlv_structure_encode(const tlv_structure_codec_t* codec,
                                        const void* value, size_t size,
                                        uint8_t* data, size_t capacity,
                                        size_t* written);
#ifdef __cplusplus
}
#endif
#endif
