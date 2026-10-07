// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#ifndef OPENTLV_TLVPP_BUILTINS_ASN1_DER_HPP
#define OPENTLV_TLVPP_BUILTINS_ASN1_DER_HPP
#include "tlv/builtins/asn1/der.h"
#include "tlv++/format.hpp"
#include "tlv/config.h"
#if OPENTLV_READER
#include "tlv++/reader/reader.hpp"
#include "tlv/builtins/asn1/der_validation.h"
#endif
#if OPENTLV_WRITER
#include "tlv++/writer/builder.hpp"
#endif
/** @file
 * @brief Generic C++ DER framing preset.
 */
namespace tlv {
/** @brief DER wire framing; semantic validation remains separate. */
namespace der {
#if OPENTLV_READER
/** @brief Explicit resource limits for canonical DER semantic validation. */
struct limits {
    size_t depth;    /**< Maximum nesting depth. */
    size_t input;    /**< Maximum total input bytes. */
    size_t value;    /**< Maximum primitive Value bytes. */
    size_t elements; /**< Maximum total elements. */
};
/**
 * @brief Validate canonical DER values and visit elements using the shared C engine.
 * @param data Borrowed immutable input.
 * @param resources Explicit resource limits.
 * @param visitor Callable receiving element_view, depth and byte offset; returns visit_control.
 * @return Success on final EOF or visitor stop, otherwise a located operation error.
 * @note Does not allocate. Returned element views borrow input and Format storage.
 */
template <typename Visitor>
expected<void, error> visit(bytes data, limits resources, Visitor&& visitor) {
    const tlv_der_limits_t        raw{resources.depth, resources.input, resources.value,
                                      resources.elements};
    detail::tree_visitor<Visitor> adapter{&visitor};
    size_t                        offset = 0;
    const auto rc = tlv_der_visit(reinterpret_cast<const uint8_t*>(data.data()), data.size(), &raw,
                                  &detail::tree_visitor<Visitor>::call, &adapter, &offset);
    if (rc != TLV_OK) return unexpected<error>(error::from_c(rc).at(offset, operation::reader));
    return {};
}
#endif
/** @brief Built-in Format satisfying the generic C++ customization contract. */
class format : public tlv::format {
public:
    /** @brief Borrow the immutable canonical descriptor without allocation. */
    format() noexcept : tlv::format(detail::format_access::borrow(tlv_format_der)) {}
};
#if OPENTLV_WRITER
/** @brief Build DER output with explicit caller-owned frames and scratch.
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

/** @brief Build DER output using bounded local stack workspace.
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
#endif

#if OPENTLV_READER
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
#endif

} // namespace der
} // namespace tlv
#endif
