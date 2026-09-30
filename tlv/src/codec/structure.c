#include "tlv/codec/structure.h"
#include "tlv/reader/visitor.h"

static int valid_descriptor(const tlv_structure_codec_t* codec) {
    return codec && tlv_format_can_read(codec->format);
}

static tlv_codec_result_t validate(const tlv_structure_codec_t* codec, const uint8_t* data,
                                   size_t size) {
    tlv_result_t rc;
    if (codec->schema) {
        rc = tlv_schema_validate(data, size, codec->format, codec->schema, codec->max_depth,
                                 codec->max_elements, NULL);
    } else {
        tlv_tree_reader_t reader;
        tlv_tree_frame_t frames[TLV_STRUCTURE_MAX_DEPTH];
        rc = tlv_tree_reader_init(&reader, data, size, codec->format, frames,
                                  TLV_STRUCTURE_MAX_DEPTH, codec->max_depth, codec->max_elements);
        if (rc == TLV_OK) rc = tlv_tree_reader_visit(&reader, NULL, NULL, NULL);
    }
    return rc == TLV_OK ? TLV_CODEC_OK : TLV_CODEC_ERR_INVALID_STRUCTURE;
}

tlv_codec_result_t tlv_structure_decode(const tlv_structure_codec_t* codec, const uint8_t* data,
                                        size_t size, void* value, size_t capacity) {
    tlv_codec_result_t rc;
    if (!valid_descriptor(codec) || !value || (!data && size)) return TLV_CODEC_ERR_NULL_ARG;
    if (!codec->decode) return TLV_CODEC_ERR_UNSUPPORTED;
    rc = validate(codec, data, size);
    if (rc != TLV_CODEC_OK) return rc;
    return codec->decode(codec->context, codec->format, data, size, value, capacity);
}

tlv_codec_result_t tlv_structure_encode(const tlv_structure_codec_t* codec, const void* value,
                                        size_t size, uint8_t* data, size_t capacity,
                                        size_t* written) {
    size_t count = 0;
    tlv_codec_result_t rc;
    if (!written) return TLV_CODEC_ERR_NULL_ARG;
    *written = 0;
    if (!valid_descriptor(codec) || !value || (!data && capacity)) return TLV_CODEC_ERR_NULL_ARG;
    if (!codec->encode) return TLV_CODEC_ERR_UNSUPPORTED;
    if (!tlv_format_can_write(codec->format)) return TLV_CODEC_ERR_NULL_ARG;
    rc = codec->encode(codec->context, codec->format, value, size, data, capacity, &count);
    if (rc != TLV_CODEC_OK) return rc;
    if (data && count > capacity) return TLV_CODEC_ERR_BUFFER_TOO_SHORT;
    if (data) {
        rc = validate(codec, data, count);
        if (rc != TLV_CODEC_OK) return rc;
    }
    *written = count;
    return TLV_CODEC_OK;
}
