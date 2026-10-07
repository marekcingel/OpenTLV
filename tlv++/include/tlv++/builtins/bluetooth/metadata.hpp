// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#ifndef OPENTLV_TLVPP_BLUETOOTH_METADATA_HPP
#define OPENTLV_TLVPP_BLUETOOTH_METADATA_HPP
#include "tlv++/types.hpp"
#include "tlv++/schema/definition.hpp"
#include "tlv/builtins/bluetooth/ad_types.h"
#include "tlv/builtins/bluetooth/company_ids.h"
#include "tlv/builtins/bluetooth/ad_data.h"
#include "tlv/builtins/bluetooth/ad_schema.h"

/** @file
 * @brief Bluetooth Advertising Data metadata and container validation.
 */
namespace tlv {
namespace bluetooth {
/** @brief Program-lifetime AD Type name, or nullptr for an unknown identifier. */
inline const char* ad_name(tlv::tag identifier) noexcept {
    const auto  raw = detail::semantic_access::get(identifier);
    const auto* entry = tlv_definition_find(&tlv_bluetooth_ad_types, &raw);
    return entry ? entry->name : nullptr;
}
/** @brief Program-lifetime company name, or nullptr for an unknown identifier. */
inline const char* company_name(uint16_t identifier) noexcept {
    const uint8_t   bytes[] = {static_cast<uint8_t>(identifier),
                               static_cast<uint8_t>(identifier >> 8)};
    const tlv_tag_t raw = {bytes, 2};
    const auto*     entry = tlv_definition_find(&tlv_bluetooth_company_ids, &raw);
    return entry ? entry->name : nullptr;
}
/** @brief Program-lifetime Advertising Data structural Schema. */
inline tlv::schema structural_schema() noexcept {
    return detail::schema_access::borrow(&tlv_bluetooth_ad_schema);
}
/** @brief Validate AD framing and padding, returning the significant input byte count.
 * @param input Immutable input, borrowed during the call only.
 * @return Significant byte count or a located canonical container error; no allocation.
 */
inline expected<size_t, error> validate_container(bytes input) {
    size_t     significant = 0, offset = 0;
    const auto rc = tlv_bluetooth_ad_data_validate(reinterpret_cast<const uint8_t*>(input.data()),
                                                   input.size(), &significant, &offset);
    if (rc != TLV_OK) return unexpected<error>(error::from_c(rc).at(offset, operation::reader));
    return significant;
}
} // namespace bluetooth
} // namespace tlv
#endif
