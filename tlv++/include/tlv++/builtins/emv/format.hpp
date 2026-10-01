#ifndef OPENTLV_CXX_BUILTINS_EMV_FORMAT_HPP
#define OPENTLV_CXX_BUILTINS_EMV_FORMAT_HPP

#include "tlv/builtins/emv/format.h"

#include "tlv++/format.hpp"
#include "tlv++/reader/reader.hpp"

/** @file
 * @brief C++ access to EMV Contact Book 3 element framing.
 */
namespace tlv {
/** @brief EMV wire framing presets. */
namespace emv {
/** @brief Built-in Format satisfying the generic C++ customization contract. */
class format : public tlv::format {
public:
    /** @brief Borrow the canonical program-lifetime descriptor without allocation. */
    format() noexcept : tlv::format(detail::format_access::borrow(tlv_format_emv)) {}
};
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
} // namespace emv

/**
 * @brief Return the immutable definite EMV BER-TLV format.
 * @return The shared C descriptor; no allocation occurs.
 * @see tlv_format_emv
 */
inline const tlv_format_t& emv_format() noexcept {
    return tlv_format_emv;
}
} // namespace tlv
#endif
