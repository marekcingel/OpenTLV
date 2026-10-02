// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#ifndef OPENTLV_TLVPP_DEFINITION_HPP
#define OPENTLV_TLVPP_DEFINITION_HPP
#include "tlv++/types.hpp"
#include "tlv/definition.h"

/** @file definition.hpp
 * @brief Borrowed generic identifier metadata and canonical registry lookup.
 */
namespace tlv {
/** @brief Identifier and optional borrowed name, without Schema or Codec policy. */
class definition {
public:
    /** @brief Associate a borrowed identifier with an optional borrowed name.
     * @param identifier Bytes that outlive this entry and all its copies.
     * @param name Optional null-terminated name with the same borrowed lifetime.
     */
    definition(tlv::tag identifier, const char* name = nullptr) noexcept
        : tag_(identifier), name_(name) {}
    /** @brief Identifier view borrowing the original immutable storage. */
    tlv::tag tag() const noexcept {
        return tag_;
    }
    /** @brief Optional borrowed null-terminated name, or nullptr. */
    const char* name() const noexcept {
        return name_;
    }

private:
    tlv::tag    tag_;
    const char* name_;
};

/** @brief Registry view; caller retains entries, identifier bytes and names. */
class definition_registry {
public:
    /** @brief Borrow an immutable registry table.
     * @param entries Definitions whose storage must outlive this view and lookup results.
     */
    explicit definition_registry(span<const definition> entries) : entries_(entries) {}
    /** @brief Look up the first matching identifier through the C engine.
     * @param tag Canonical identifier, borrowed for this call.
     * @return Borrowed table entry, or nullptr when no entry matches.
     */
    TLV_NODISCARD const definition* find(tlv::tag tag) const {
        const auto wanted = detail::semantic_access::get(tag);
        for (size_t i = 0; i < entries_.size(); ++i) {
            const tlv_definition_t          entry{detail::semantic_access::get(entries_[i].tag()),
                                                  entries_[i].name()};
            const tlv_definition_registry_t registry{&entry, 1};
            if (tlv_definition_find(&registry, &wanted)) return &entries_[i];
        }
        return nullptr;
    }

private:
    span<const definition> entries_;
};
} // namespace tlv
#endif
