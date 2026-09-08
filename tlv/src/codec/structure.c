#include "tlv/codec/structure.h"
#include "tlv/reader/walker.h"

static int valid_descriptor(const tlv_structure_codec_t* codec) {
    return codec && codec->format && codec->format->read_tag &&
        codec->format->read_length;
}

static tlv_codec_result_t validate(const tlv_structure_codec_t* codec,
                                    const uint8_t* data, size_t size) {
    tlv_result_t rc = codec->schema ?
        tlv_schema_validate(data, size, codec->format, codec->schema,
                            codec->max_depth, codec->max_elements, NULL) :
        tlv_walk_tree(data, size, codec->format, codec->max_depth,
                       codec->max_elements, NULL, NULL, NULL);
    return rc == TLV_OK ? TLV_CODEC_OK : TLV_CODEC_ERR_INVALID_STRUCTURE;
}

tlv_codec_result_t tlv_structure_decode(const tlv_structure_codec_t* codec,
                                        const uint8_t* data, size_t size,
                                        void* value, size_t capacity) {
    tlv_codec_result_t rc;
    if (!valid_descriptor(codec) || !value || (!data && size))
        return TLV_CODEC_ERR_NULL_ARG;
    if (codec->max_depth > TLV_WALK_MAX_DEPTH) return TLV_CODEC_ERR_INVALID_VALUE;
    if (!codec->decode) return TLV_CODEC_ERR_UNSUPPORTED;
    rc = validate(codec, data, size);
    if (rc != TLV_CODEC_OK) return rc;
    return codec->decode(codec->context, codec->format, data, size, value, capacity);
}

tlv_codec_result_t tlv_structure_encode(const tlv_structure_codec_t* codec,
                                        const void* value, size_t size,
                                        uint8_t* data, size_t capacity,
                                        size_t* written) {
    size_t count = 0;
    tlv_codec_result_t rc;
    if (!written) return TLV_CODEC_ERR_NULL_ARG;
    *written = 0;
    if (!valid_descriptor(codec) || !value || (!data && capacity))
        return TLV_CODEC_ERR_NULL_ARG;
    if (codec->max_depth > TLV_WALK_MAX_DEPTH) return TLV_CODEC_ERR_INVALID_VALUE;
    if (!codec->encode) return TLV_CODEC_ERR_UNSUPPORTED;
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
