#ifndef OPENTLV_DER_PROFILE_INTERNAL_H
#define OPENTLV_DER_PROFILE_INTERNAL_H
#include "tlv/builtins/asn1/der_profile.h"
#include "tlv/view.h"
#include <stddef.h>
#include <stdint.h>

/* Parses one element's header (tag and length) from data[0..size), checking
 * it against limits->max_value_size and the available buffer. base is data's
 * absolute offset within the original input, used only to compute
 * error_offset. On success, *view holds the tag and a value borrowing data,
 * and *consumed is the complete element size (tag + length + value).
 * Outputs are unchanged on failure. Shared by tlv_der_read/walk/write's
 * traversal and the schema-aware DER validator/encoder. */
tlv_result_t tlv_der_read_entry(const uint8_t* data, size_t size, size_t base,
                                const tlv_der_limits_t* limits, tlv_view_t* view, size_t* consumed,
                                size_t* error_offset);

#endif /* OPENTLV_DER_PROFILE_INTERNAL_H */
