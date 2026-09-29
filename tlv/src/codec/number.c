#include "tlv/codec/number.h"
#include "tlv/endian.h"
#include <string.h>

static int valid_config(const tlv_number_codec_config_t* config) {
    if (!config->min_length || !config->length_step || config->min_length > config->max_length)
        return 0;
    if (config->encoding == TLV_NUMBER_BCD)
        return config->max_length <= 9 && config->digits >= 1 && config->digits <= 18;
    return (config->encoding == TLV_NUMBER_BINARY_BE || config->encoding == TLV_NUMBER_BINARY_LE) &&
           config->max_length <= 8 && config->digits == 0;
}

static uint64_t decimal_limit(unsigned digits) {
    uint64_t limit = 1;
    while (digits--) limit *= 10;
    return limit - 1;
}

tlv_codec_result_t tlv_number_decode(const void* context, const uint8_t* data, size_t size,
                                     void* value, size_t capacity) {
    const tlv_number_codec_config_t* config = (const tlv_number_codec_config_t*)context;
    uint64_t number = 0;
    size_t i;
    if (!config || !value || (!data && size)) return TLV_CODEC_ERR_NULL_ARG;
    if (!valid_config(config) || size < config->min_length || size > config->max_length ||
        (size - config->min_length) % config->length_step)
        return TLV_CODEC_ERR_INVALID_VALUE;
    if (config->encoding == TLV_NUMBER_BCD) {
        for (i = 0; i < size; ++i) {
            unsigned high = data[i] >> 4, low = data[i] & 15;
            if (high > 9 || low > 9) return TLV_CODEC_ERR_INVALID_VALUE;
            number = number * 100 + high * 10 + low;
        }
        if (number > decimal_limit(config->digits)) return TLV_CODEC_ERR_INVALID_VALUE;
    } else {
        tlv_byte_order_t order = config->encoding == TLV_NUMBER_BINARY_BE
                                     ? TLV_BYTE_ORDER_BIG_ENDIAN
                                     : TLV_BYTE_ORDER_LITTLE_ENDIAN;
        if (tlv_read_uint(data, size, order, &number) != TLV_OK) return TLV_CODEC_ERR_INVALID_VALUE;
    }
    if (capacity < sizeof(number)) return TLV_CODEC_ERR_BUFFER_TOO_SHORT;
    memcpy(value, &number, sizeof(number));
    return TLV_CODEC_OK;
}

tlv_codec_result_t tlv_number_encode(const void* context, const void* value, size_t size,
                                     uint8_t* data, size_t capacity, size_t* written) {
    const tlv_number_codec_config_t* config = (const tlv_number_codec_config_t*)context;
    uint64_t number, remaining;
    uint8_t bytes[9] = {0};
    size_t width = 1, i;
    unsigned radix;
    if (!written) return TLV_CODEC_ERR_NULL_ARG;
    *written = 0;
    if (!config || !value || (!data && capacity)) return TLV_CODEC_ERR_NULL_ARG;
    if (!valid_config(config) || size != sizeof(number)) return TLV_CODEC_ERR_INVALID_VALUE;
    memcpy(&number, value, sizeof(number));
    if (config->encoding == TLV_NUMBER_BCD && number > decimal_limit(config->digits))
        return TLV_CODEC_ERR_INVALID_VALUE;
    radix = config->encoding == TLV_NUMBER_BCD ? 100 : 256;
    remaining = number;
    while (remaining >= radix) {
        remaining /= radix;
        ++width;
    }
    if (width < config->min_length) width = config->min_length;
    while (width <= config->max_length && (width - config->min_length) % config->length_step)
        ++width;
    if (width > config->max_length) return TLV_CODEC_ERR_INVALID_VALUE;
    if (data && capacity < width) return TLV_CODEC_ERR_BUFFER_TOO_SHORT;
    if (config->encoding == TLV_NUMBER_BCD) {
        for (i = width; i > 0; --i) {
            unsigned pair = (unsigned)(number % 100);
            bytes[i - 1] = (uint8_t)(((pair / 10) << 4) | (pair % 10));
            number /= 100;
        }
    } else {
        tlv_byte_order_t order = config->encoding == TLV_NUMBER_BINARY_BE
                                     ? TLV_BYTE_ORDER_BIG_ENDIAN
                                     : TLV_BYTE_ORDER_LITTLE_ENDIAN;
        if (tlv_write_uint(bytes, width, order, number) != TLV_OK)
            return TLV_CODEC_ERR_INVALID_VALUE;
    }
    if (data) memcpy(data, bytes, width);
    *written = width;
    return TLV_CODEC_OK;
}
