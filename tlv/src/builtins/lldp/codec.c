#include "tlv/builtins/lldp/codec.h"
#include <string.h>
#include "tlv/codec/values.h"
#include "tlv/endian.h"

enum { CHASSIS, PORT, TTL, TEXT, CAPABILITIES, MANAGEMENT, ORGANISATION };

static int address_valid(uint8_t family, size_t size) {
    return family != 0 && size != 0 && (family != 1 || size == 4) && (family != 2 || size == 16);
}
static int id_valid(int kind, uint8_t subtype, const uint8_t* p, size_t size) {
    const uint8_t mac = (uint8_t)(kind == CHASSIS ? 4 : 3);
    if (subtype < 1 || subtype > 7 || size < 1 || size > 255) return 0;
    if (subtype == mac) return size == 6;
    if (subtype == mac + 1) return size >= 2 && address_valid(p[0], size - 1);
    return 1;
}
static tlv_codec_result_t span_size(tlv_value_t value, size_t max, size_t* size) {
    if (!value.data && value.size) return TLV_CODEC_ERR_NULL_ARG;
    if (value.size > max || tlv_size_to_native(value.size, size) != TLV_OK)
        return TLV_CODEC_ERR_INVALID_VALUE;
    return TLV_CODEC_OK;
}

static tlv_codec_result_t decode(const void* context, const uint8_t* data, size_t size, void* value,
                                 size_t capacity) {
    const int kind = *(const int*)context;
#define RETURN_VALUE(result)                                                                       \
    do {                                                                                           \
        if (capacity < sizeof(result)) return TLV_CODEC_ERR_BUFFER_TOO_SHORT;                      \
        memcpy(value, &(result), sizeof(result));                                                  \
        return TLV_CODEC_OK;                                                                       \
    } while (0)
    switch (kind) {
        case CHASSIS:
        case PORT: {
            tlv_lldp_id_t result;
            if (size < 2 || size > 256 || !id_valid(kind, data[0], data + 1, size - 1))
                return TLV_CODEC_ERR_INVALID_VALUE;
            result.subtype = data[0];
            result.identifier = (tlv_value_t){data + 1, size - 1};
            RETURN_VALUE(result);
        }
        case TTL: return tlv_codec_decode(&tlv_codec_uint16_be, data, size, value, capacity);
        case TEXT: {
            if (size > 255) return TLV_CODEC_ERR_INVALID_VALUE;
            return tlv_codec_decode(&tlv_codec_bytes, data, size, value, capacity);
        }
        case CAPABILITIES: {
            tlv_lldp_capabilities_t result;
            if (size != 4) return TLV_CODEC_ERR_INVALID_VALUE;
            result.supported = tlv_read_u16_be(data);
            result.enabled = tlv_read_u16_be(data + 2);
            if ((result.enabled & (uint16_t)~result.supported) != 0)
                return TLV_CODEC_ERR_INVALID_VALUE;
            RETURN_VALUE(result);
        }
        case MANAGEMENT: {
            tlv_lldp_management_address_t result;
            size_t address_length, offset, oid_length;
            if (size < 9) return TLV_CODEC_ERR_INVALID_VALUE;
            address_length = data[0]; /* Includes the family octet. */
            if (address_length < 2 || address_length > 32 || address_length > size - 7)
                return TLV_CODEC_ERR_INVALID_VALUE;
            result.address_subtype = data[1];
            result.address = (tlv_value_t){data + 2, address_length - 1};
            if (!address_valid(result.address_subtype, address_length - 1))
                return TLV_CODEC_ERR_INVALID_VALUE;
            offset = 1 + address_length;
            result.interface_subtype = data[offset];
            if (result.interface_subtype < 1 || result.interface_subtype > 3)
                return TLV_CODEC_ERR_INVALID_VALUE;
            result.interface_number = ((uint32_t)data[offset + 1] << 24) |
                                      ((uint32_t)data[offset + 2] << 16) |
                                      ((uint32_t)data[offset + 3] << 8) | data[offset + 4];
            oid_length = data[offset + 5];
            if (oid_length > 128 || oid_length != size - offset - 6)
                return TLV_CODEC_ERR_INVALID_VALUE;
            result.oid = (tlv_value_t){data + offset + 6, oid_length};
            RETURN_VALUE(result);
        }
        case ORGANISATION: {
            tlv_lldp_organisation_t result;
            if (size < 4 || size > 511) return TLV_CODEC_ERR_INVALID_VALUE;
            memcpy(result.oui, data, 3);
            result.subtype = data[3];
            result.payload = (tlv_value_t){data + 4, size - 4};
            RETURN_VALUE(result);
        }
        default: return TLV_CODEC_ERR_UNSUPPORTED;
    }
#undef RETURN_VALUE
}

static tlv_codec_result_t encode(const void* context, const void* value, size_t size, uint8_t* data,
                                 size_t capacity, size_t* written) {
    const int kind = *(const int*)context;
    uint8_t wire[511];
    size_t length = 0, count = 0;
    tlv_codec_result_t rc;
#define READ_VALUE(input)                                                                          \
    do {                                                                                           \
        if (size != sizeof(input)) return TLV_CODEC_ERR_INVALID_VALUE;                             \
        memcpy(&(input), value, sizeof(input));                                                    \
    } while (0)
    switch (kind) {
        case CHASSIS:
        case PORT: {
            tlv_lldp_id_t input;
            READ_VALUE(input);
            rc = span_size(input.identifier, 255, &count);
            if (rc != TLV_CODEC_OK) return rc;
            if (!id_valid(kind, input.subtype, input.identifier.data, count))
                return TLV_CODEC_ERR_INVALID_VALUE;
            wire[0] = input.subtype;
            memcpy(wire + 1, input.identifier.data, count);
            length = 1 + count;
            break;
        }
        case TTL:
            return tlv_codec_encode(&tlv_codec_uint16_be, value, size, data, capacity, written);
        case TEXT: {
            tlv_value_t input;
            READ_VALUE(input);
            rc = span_size(input, 255, &length);
            if (rc != TLV_CODEC_OK) return rc;
            return tlv_codec_encode(&tlv_codec_bytes, value, size, data, capacity, written);
        }
        case CAPABILITIES: {
            tlv_lldp_capabilities_t input;
            READ_VALUE(input);
            if ((input.enabled & (uint16_t)~input.supported) != 0)
                return TLV_CODEC_ERR_INVALID_VALUE;
            tlv_write_u16_be(wire, input.supported);
            tlv_write_u16_be(wire + 2, input.enabled);
            length = 4;
            break;
        }
        case MANAGEMENT: {
            tlv_lldp_management_address_t input;
            size_t oid_length, offset;
            READ_VALUE(input);
            rc = span_size(input.address, 31, &count);
            if (rc != TLV_CODEC_OK) return rc;
            rc = span_size(input.oid, 128, &oid_length);
            if (rc != TLV_CODEC_OK) return rc;
            if (!address_valid(input.address_subtype, count) || input.interface_subtype < 1 ||
                input.interface_subtype > 3)
                return TLV_CODEC_ERR_INVALID_VALUE;
            wire[0] = (uint8_t)(count + 1);
            wire[1] = input.address_subtype;
            memcpy(wire + 2, input.address.data, count);
            offset = count + 2;
            wire[offset] = input.interface_subtype;
            wire[offset + 1] = (uint8_t)(input.interface_number >> 24);
            wire[offset + 2] = (uint8_t)(input.interface_number >> 16);
            wire[offset + 3] = (uint8_t)(input.interface_number >> 8);
            wire[offset + 4] = (uint8_t)input.interface_number;
            wire[offset + 5] = (uint8_t)oid_length;
            if (oid_length) memcpy(wire + offset + 6, input.oid.data, oid_length);
            length = offset + 6 + oid_length;
            break;
        }
        case ORGANISATION: {
            tlv_lldp_organisation_t input;
            READ_VALUE(input);
            rc = span_size(input.payload, 507, &count);
            if (rc != TLV_CODEC_OK) return rc;
            memcpy(wire, input.oui, 3);
            wire[3] = input.subtype;
            if (count) memcpy(wire + 4, input.payload.data, count);
            length = 4 + count;
            break;
        }
        default: return TLV_CODEC_ERR_UNSUPPORTED;
    }
#undef READ_VALUE
    if (data) {
        if (capacity < length) return TLV_CODEC_ERR_BUFFER_TOO_SHORT;
        if (length) memcpy(data, wire, length);
    }
    *written = length;
    return TLV_CODEC_OK;
}

#define CODEC(name, kind)                                                                          \
    static const int name##_kind = kind;                                                           \
    const tlv_codec_t tlv_lldp_codec_##name = {&name##_kind, decode, encode}
CODEC(chassis_id, CHASSIS);
CODEC(port_id, PORT);
CODEC(ttl, TTL);
CODEC(text, TEXT);
CODEC(capabilities, CAPABILITIES);
CODEC(management_address, MANAGEMENT);
CODEC(organisation, ORGANISATION);
#undef CODEC
