#ifndef OPENTLV_TLVPP_SCHEMA_HPP
#define OPENTLV_TLVPP_SCHEMA_HPP
#include "tlv++/types.hpp"
#include "tlv/schemas/schema.h"

namespace tlv {
TLV_NODISCARD inline expected<void, error>
validate(bytes data, const tlv_format_t& format, const tlv_structure_schema_t& schema,
         size_t max_depth, size_t max_elements, size_t* error_offset = nullptr) {
    tlv_result_t rc = tlv_schema_validate(reinterpret_cast<const uint8_t*>(data.data()),
        data.size(), &format, &schema, max_depth, max_elements, error_offset);
    if (rc != TLV_OK) return unexpected<error>(error::from_c(rc));
    return {};
}
}
#endif
