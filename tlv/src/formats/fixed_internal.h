#ifndef OPENTLV_FIXED_INTERNAL_H
#define OPENTLV_FIXED_INTERNAL_H
#include "tlv/format.h"
#include "tlv/formats/fixed.h"

/* The TLV_ELEMENT_ORDER_LTV whole-element read/write pair from fixed.c,
 * exposed so protocol-specific presets (for example Bluetooth LTV) can build
 * a tlv_format_t directly from a static const tlv_fixed_format_t without
 * reimplementing the LTV parsing/encoding logic or paying for a runtime
 * tlv_fixed_format_init() call. */
tlv_result_t tlv_fixed_read_element_ltv(const void* context, const uint8_t* data, size_t size,
                                        tlv_tag_t* tag, size_t* header_size, size_t* value_size,
                                        size_t* trailer_size);
tlv_result_t tlv_fixed_write_header_ltv(const void* context, uint8_t* data, size_t capacity,
                                        const tlv_tag_t* tag, size_t length, size_t* written);
#endif
