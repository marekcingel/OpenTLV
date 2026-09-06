#include "tlv/endian.h"

uint16_t tlv_read_u16_be(const uint8_t* data) {
    return (uint16_t)(((uint32_t)data[0] << 8) |
                       ((uint32_t)data[1] << 0));
}

uint16_t tlv_read_u16_le(const uint8_t* data) {
    return (uint16_t)(((uint32_t)data[0] << 0) |
                       ((uint32_t)data[1] << 8));
}

uint32_t tlv_read_u32_be(const uint8_t* data) {
    return (uint32_t)(((uint32_t)data[0] << 24) |
                       ((uint32_t)data[1] << 16) |
                       ((uint32_t)data[2] << 8) |
                       ((uint32_t)data[3] << 0));
}

uint32_t tlv_read_u32_le(const uint8_t* data) {
    return (uint32_t)(((uint32_t)data[0] << 0) |
                       ((uint32_t)data[1] << 8) |
                       ((uint32_t)data[2] << 16) |
                       ((uint32_t)data[3] << 24));
}

void tlv_write_u16_be(uint8_t* data, uint16_t value) {
    data[0] = (uint8_t)(value >> 8);
    data[1] = (uint8_t)(value >> 0);
}

void tlv_write_u16_le(uint8_t* data, uint16_t value) {
    data[0] = (uint8_t)(value >> 0);
    data[1] = (uint8_t)(value >> 8);
}

void tlv_write_u32_be(uint8_t* data, uint32_t value) {
    data[0] = (uint8_t)(value >> 24);
    data[1] = (uint8_t)(value >> 16);
    data[2] = (uint8_t)(value >> 8);
    data[3] = (uint8_t)(value >> 0);
}

void tlv_write_u32_le(uint8_t* data, uint32_t value) {
    data[0] = (uint8_t)(value >> 0);
    data[1] = (uint8_t)(value >> 8);
    data[2] = (uint8_t)(value >> 16);
    data[3] = (uint8_t)(value >> 24);
}
