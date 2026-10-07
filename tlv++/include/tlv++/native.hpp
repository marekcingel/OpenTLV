// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#ifndef OPENTLV_TLVPP_NATIVE_HPP
#define OPENTLV_TLVPP_NATIVE_HPP

#include "tlv++/format.hpp"
#include "tlv/config.h"
#if OPENTLV_QUERY && OPENTLV_READER
#include "tlv++/query/query.hpp"
#include "tlv++/query/options.hpp"
#include "tlv++/query/program.hpp"
#endif
#if OPENTLV_CODEC
#include "tlv++/codec/dynamic.hpp"
#include "tlv++/codec/typed.hpp"
#endif
#if OPENTLV_SCHEMA
#include "tlv++/schema/definition.hpp"
#endif
#if OPENTLV_DOCUMENT && OPENTLV_READER && OPENTLV_WRITER && OPENTLV_QUERY && OPENTLV_CODEC
#include "tlv++/document/document.hpp"
#endif

/** @file
 * @brief Explicit interoperability with the canonical C engine.
 * @note Include this header explicitly when mixing the C and C++ APIs.
 */
namespace tlv {
/** @brief Explicit C interoperability; ordinary C++ code uses public C++ types. */
namespace native {
#if OPENTLV_QUERY && OPENTLV_READER
/** @brief Borrow an immutable native program; its owner and providers must outlive use. */
inline const tlv_query_program_t* handle(const query_program& value) noexcept {
    return detail::query_program_access::get(value);
}
/** @brief Reject borrowing a native program from a temporary owner. */
const tlv_query_program_t* handle(query_program&&) = delete;
/** @brief Reject borrowing a native program from a const temporary owner. */
const tlv_query_program_t* handle(const query_program&&) = delete;
/** @brief Borrow a mutable continuation; its owner and borrowed inputs must outlive use. */
inline tlv_query_exec_t* handle(query_execution& value) noexcept {
    return detail::query_program_access::get(value);
}
/** @brief Explicitly borrow native compiler settings; all referenced state remains borrowed. */
inline query_settings borrow_query_settings(const tlv_query_compile_options_t* value) noexcept {
    return detail::query_options_access::borrow(value);
}
/** @brief Explicitly borrow native Query capabilities, including an absent environment. */
inline query_capabilities borrow_query_capabilities(const tlv_query_environment_t* value) noexcept {
    return detail::query_options_access::borrow(value);
}
/** @brief Borrow a parsed native path; the C++ Query owner must outlive its use. */
inline const tlv_query_t& descriptor(const query& value) noexcept {
    return detail::query_access::get(value);
}
/** @brief Reject descriptor borrowing from a temporary Query. */
const tlv_query_t& descriptor(query&&) = delete;
/** @brief Reject descriptor borrowing from a const temporary Query. */
const tlv_query_t& descriptor(const query&&) = delete;
#endif

#if OPENTLV_CODEC
/** @brief Explicit typed adaptation of an immutable C Value Codec descriptor.
 * @tparam T Exact C representation documented by Descriptor.
 * @tparam Descriptor Program-lifetime canonical C Codec; context remains borrowed.
 */
template <typename T, const tlv_codec_t* Descriptor>
using codec_adapter = detail::codec_adapter<T, Descriptor>;
/** @brief Borrow an immutable C Codec and context for explicit runtime interoperability.
 * @warning Descriptor and context must outlive all uses; representation types must match.
 */
inline dynamic_codec borrow_codec(const tlv_codec_t& descriptor) noexcept {
    return detail::codec_access::borrow(&descriptor);
}
/** @brief Reject a dangling view into a temporary C Codec. */
dynamic_codec borrow_codec(tlv_codec_t&&) = delete;
/** @brief Reject a dangling view into a const temporary C Codec. */
dynamic_codec borrow_codec(const tlv_codec_t&&) = delete;
/** @brief Access a borrowed runtime Codec, or nullptr for an absent codec. */
inline const tlv_codec_t* descriptor(dynamic_codec view) noexcept {
    return detail::codec_access::get(view);
}
#endif
#if OPENTLV_SCHEMA
/** @brief Borrow a C structural Schema for explicit interoperability without allocation.
 * @warning All tables, identifier bytes and names must outlive uses of the returned view.
 */
inline schema borrow_schema(const tlv_structure_schema_t& descriptor) noexcept {
    return detail::schema_access::borrow(&descriptor);
}
/** @brief Reject borrowing a temporary Schema descriptor. */
schema borrow_schema(tlv_structure_schema_t&&) = delete;
/** @brief Reject borrowing a const temporary Schema descriptor. */
schema borrow_schema(const tlv_structure_schema_t&&) = delete;
/** @brief Access the immutable borrowed Schema descriptor, or nullptr for an absent Schema. */
inline const tlv_structure_schema_t* descriptor(schema view) noexcept {
    return detail::schema_access::get(view);
}
#endif

#if OPENTLV_DOCUMENT && OPENTLV_READER && OPENTLV_WRITER && OPENTLV_QUERY && OPENTLV_CODEC
/** @brief Borrow a mutable native Document for explicit interoperability; never free it.
 * @warning Pointer must not outlive the owner. Edits preserve checked C++ handle invalidation. */
inline tlv_document_t* handle(document& value) {
    return detail::document_access::get(value);
}
/** @brief Borrow a read-only native Document; never free it or outlive its owner. */
inline const tlv_document_t* handle(const document& value) {
    return detail::document_access::get(value);
}
/** @brief Borrow a mutable native Node, or nullptr if invalid; never free its owner. */
inline tlv_node_t* handle(const node& value) {
    return detail::document_access::get(value);
}
/** @brief Borrow a read-only native Node, or nullptr if invalid. */
inline const tlv_node_t* handle(const const_node& value) {
    return detail::document_access::get(value);
}
#endif

/**
 * @brief Borrow an existing immutable C Format without copying or allocation.
 * @param descriptor Caller-owned descriptor; invalid callbacks are reported by operations.
 * @return A C++ view of exactly this descriptor, including its original context.
 * @warning Descriptor and context must remain alive and unchanged for every
 * dependent Reader, Writer and retained source view. Temporary descriptors are rejected.
 */
inline tlv::format borrow_format(const tlv_format_t& descriptor) noexcept {
    return detail::format_access::borrow(descriptor);
}

/** @brief Reject borrowing a temporary descriptor whose lifetime would end immediately. */
tlv::format borrow_format(tlv_format_t&&) = delete;
/** @brief Reject borrowing a const temporary descriptor. */
tlv::format borrow_format(const tlv_format_t&&) = delete;

/**
 * @brief Access the borrowed native descriptor for an explicit C API operation.
 * @param view C++ Format view; copying or destroying it does not change the descriptor.
 * @return Immutable descriptor reference; no copy or allocation occurs.
 * @warning The descriptor and context retain their original borrowed lifetime.
 */
inline const tlv_format_t& descriptor(tlv::format view) noexcept {
    return detail::format_access::get(view);
}

/**
 * @brief Validate and borrow native identifier bytes without copying.
 * @param raw Native descriptor; underlying immutable bytes must outlive all views.
 * @return Tag, or TLV_ERR_NULL_ARG for null storage with nonzero size.
 * @note The caller remains responsible for the actual storage extent.
 */
TLV_NODISCARD inline expected<tlv::tag, error> borrow_tag(tlv_tag_t raw) {
    if (!raw.data && raw.size) return unexpected<error>(error::from_c(TLV_ERR_NULL_ARG));
    return detail::semantic_access::borrow(raw);
}

/**
 * @brief Validate and borrow a native Value without copying.
 * @param raw Native descriptor; immutable storage must outlive every view.
 * @return Value view, TLV_ERR_NULL_ARG for invalid storage, or TLV_ERR_NATIVE_SIZE
 * if the logical length cannot be addressed by size_t.
 * @note Validation cannot prove the storage extent.
 */
TLV_NODISCARD inline expected<value_view, error> borrow_value(tlv_value_t raw) {
    const auto rc = tlv_value_validate(&raw);
    if (rc != TLV_OK) return unexpected<error>(error::from_c(rc));
    return detail::semantic_access::borrow(raw);
}

/**
 * @brief Validate and borrow a native semantic Element without copying bytes.
 * @param raw Descriptor whose immutable Tag and Value storage outlives every view.
 * @return Element view or the original Tag/Value representation error.
 */
TLV_NODISCARD inline expected<element_view, error> borrow_element(tlv_element_t raw) {
    auto identifier = borrow_tag(raw.tag);
    if (!identifier) return unexpected<error>(identifier.error());
    auto value = borrow_value(raw.value);
    if (!value) return unexpected<error>(value.error());
    return element_view(*identifier, *value);
}

/** @brief Export a shallow C Tag descriptor; storage retains its borrowed lifetime. */
inline tlv_tag_t descriptor(tlv::tag view) noexcept {
    return detail::semantic_access::get(view);
}
/** @brief Export a shallow C Value descriptor; storage retains its borrowed lifetime. */
inline tlv_value_t descriptor(value_view view) noexcept {
    return detail::semantic_access::get(view);
}
/** @brief Export a shallow C Element descriptor; neither descriptor nor bytes are retained. */
inline tlv_element_t descriptor(element_view view) noexcept {
    return detail::semantic_access::get(view);
}

} // namespace native
} // namespace tlv
#endif
