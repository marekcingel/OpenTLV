#include "tlv/builtins/lldp/lldp.h"
#include <string.h>

/* Canonical Type bytes must survive subsequent decodes and shallow copies. */
static const uint8_t identifiers[128] = {
    0,   1,   2,   3,   4,   5,   6,   7,   8,   9,   10,  11,  12,  13,  14,  15,  16,  17,  18,
    19,  20,  21,  22,  23,  24,  25,  26,  27,  28,  29,  30,  31,  32,  33,  34,  35,  36,  37,
    38,  39,  40,  41,  42,  43,  44,  45,  46,  47,  48,  49,  50,  51,  52,  53,  54,  55,  56,
    57,  58,  59,  60,  61,  62,  63,  64,  65,  66,  67,  68,  69,  70,  71,  72,  73,  74,  75,
    76,  77,  78,  79,  80,  81,  82,  83,  84,  85,  86,  87,  88,  89,  90,  91,  92,  93,  94,
    95,  96,  97,  98,  99,  100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113,
    114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127};

static tlv_result_t decode(const void* context, const uint8_t* data, size_t size,
                           tlv_decoded_t* result, tlv_format_error_t* error) {
    size_t length;
    (void)context;
    error->region = TLV_REGION_HEADER;
    error->has_offset = 1;
    error->offset = 0;
    error->has_required = 1;
    error->required = 2;
    if (size < 2) return TLV_ERR_BUFFER_TOO_SHORT;
    error->tag = (tlv_range_t){0, 1, 1};
    error->length = (tlv_range_t){0, 2, 1};
    length = ((size_t)(data[0] & 1) << 8) | data[1];
    error->region = TLV_REGION_VALUE;
    error->offset = 2;
    error->required = length;
    error->value = (tlv_range_t){2, length <= size - 2 ? length : size - 2, 1};
    if (length > size - 2) return TLV_ERR_BUFFER_TOO_SHORT;
    result->element.tag = tlv_tag(identifiers + (data[0] >> 1), 1);
    result->element.value = (tlv_value_t){data + 2, length};
    result->source.header = (tlv_range_t){0, 2, 1};
    result->source.tag = error->tag;
    result->source.length = error->length;
    result->source.value = (tlv_range_t){2, length, 1};
    result->source.trailer = (tlv_range_t){2 + length, 0, 1};
    result->source.size = 2 + length;
    result->source.tag_binding = TLV_TAG_BINDING_FORMAT;
    return TLV_OK;
}

static tlv_result_t measure(const void* context, const tlv_element_t* element,
                            tlv_encoding_t* result, tlv_format_error_t* error) {
    (void)context;
    error->region = TLV_REGION_TAG;
    error->has_offset = 1;
    error->offset = 0;
    if (element->tag.size != 1) return TLV_ERR_INVALID_TAG_SIZE;
    if (element->tag.data[0] > 127) return TLV_ERR_INVALID_TAG;
    error->region = TLV_REGION_LENGTH;
    if (element->value.size > 511) return TLV_ERR_INVALID_LENGTH;
    *result = (tlv_encoding_t){2, element->value.size, 0, 2 + element->value.size};
    return TLV_OK;
}

static tlv_result_t encode(const void* context, const tlv_element_t* element, uint8_t* data,
                           size_t capacity, size_t* written, tlv_format_error_t* error) {
    tlv_encoding_t sizes;
    size_t length;
    tlv_result_t rc = measure(context, element, &sizes, error);
    if (rc != TLV_OK) return rc;
    /* The validated 0..511 range fits every supported native size_t. */
    length = (size_t)element->value.size;
    if (capacity < length + 2) return TLV_ERR_BUFFER_TOO_SHORT;
    data[0] = (uint8_t)((element->tag.data[0] << 1) | (length >> 8));
    data[1] = (uint8_t)(length & 0xff);
    if (length) memcpy(data + 2, element->value.data, length);
    *written = length + 2;
    return TLV_OK;
}

const tlv_format_t tlv_format_lldp = {NULL, decode, measure, encode, NULL};

static const tlv_definition_t types[] = {{{identifiers + 0, 1}, "End of LLDPDU"},
                                         {{identifiers + 1, 1}, "Chassis ID"},
                                         {{identifiers + 2, 1}, "Port ID"},
                                         {{identifiers + 3, 1}, "Time To Live"},
                                         {{identifiers + 4, 1}, "Port Description"},
                                         {{identifiers + 5, 1}, "System Name"},
                                         {{identifiers + 6, 1}, "System Description"},
                                         {{identifiers + 7, 1}, "System Capabilities"},
                                         {{identifiers + 8, 1}, "Management Address"},
                                         {{identifiers + 127, 1}, "Organisationally Specific"}};
const tlv_definition_registry_t tlv_lldp_types = {types, sizeof(types) / sizeof(types[0])};
