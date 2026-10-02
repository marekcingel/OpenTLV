// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#ifndef OPENTLV_TLVPP_BUILTINS_DHCP_DHCPV4_HPP
#define OPENTLV_TLVPP_BUILTINS_DHCP_DHCPV4_HPP

#include "tlv/builtins/dhcp/dhcpv4.h"

#include "tlv++/format.hpp"
#include "tlv++/reader/reader.hpp"
#include "tlv++/writer/builder.hpp"

/** @file
 * @brief C++ preset for DHCPv4 option framing using the shared C descriptor.
 */
namespace tlv {
/** @brief DHCP wire framing presets. */
namespace dhcp {
/** @brief Built-in Format satisfying the generic C++ customization contract. */
class format : public tlv::format {
public:
    /** @brief Borrow the canonical program-lifetime descriptor without allocation. */
    format() noexcept : tlv::format(detail::format_access::borrow(tlv_format_dhcpv4)) {}
};
/** @brief Build DHCP output with explicit caller-owned frames and scratch.
 * @param output Borrowed mutable byte span, array or contiguous byte container.
 * @param workspace Disjoint construction storage, never resized.
 * @param callback Callable taking writer_builder& and returning void; called once.
 * @param diagnostic Optional canonical C Writer failure detail.
 * @return Exact written size or allocation-free first failure; exceptions propagate.
 * @see tlv::encode
 */
template <typename Output, typename Callback>
TLV_NODISCARD expected<size_t, writer_failure> encode(Output&& output, writer_workspace workspace,
                                                      Callback&&         callback,
                                                      writer_diagnostic* diagnostic = nullptr) {
    return tlv::encode<format>(std::forward<Output>(output), workspace,
                               std::forward<Callback>(callback), format{}, diagnostic);
}

/** @brief Build DHCP output using bounded local stack workspace.
 * @tparam ScratchCapacity Scratch bytes, default 1024; must fit the largest closed Value.
 * @tparam Depth Frame count and maximum item depth, default TLV_TREE_DEFAULT_DEPTH.
 * @param output Caller-owned mutable byte span, array or contiguous byte container.
 * @param callback Scoped writes taking writer_builder& and returning void, invoked once.
 * @param diagnostic Optional canonical C Writer failure detail.
 * @return Exact byte count or first failure; workspace never grows or allocates.
 */
template <size_t ScratchCapacity = 1024, size_t Depth = TLV_TREE_DEFAULT_DEPTH, typename Output,
          typename Callback>
TLV_NODISCARD expected<size_t, writer_failure> encode(Output&& output, Callback&& callback,
                                                      writer_diagnostic* diagnostic = nullptr) {
    return tlv::encode<format, ScratchCapacity, Depth>(
        std::forward<Output>(output), std::forward<Callback>(callback), format{}, diagnostic);
}
/**
 * @brief Parse final input as borrowed Elements using the built-in Format.
 * @param data Immutable borrowed final input.
 * @return Allocation-free single-pass range; no Schema or Value validation is performed.
 * @throws parse_error During iteration on any failure other than final EOF.
 * @warning Input must outlive the range and every retained Element or diagnostic.
 * @see tlv::parse
 */
TLV_NODISCARD inline detail::parsing_range<format> parse(bytes data) {
    return tlv::parse<format>(data);
}
} // namespace dhcp

/**
 * @brief Returns the immutable DHCPv4 option framing preset.
 * @return The shared C descriptor with static lifetime.
 * @note Requires `OPENTLV_DHCP=ON`. The caller handles End and packet semantics.
 * @see tlv_format_dhcpv4
 */
inline const tlv_format_t& dhcpv4_format() noexcept {
    return tlv_format_dhcpv4;
}
} // namespace tlv
#endif
