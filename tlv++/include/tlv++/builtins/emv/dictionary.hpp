// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#ifndef OPENTLV_TLVPP_EMV_DICTIONARY_HPP
#define OPENTLV_TLVPP_EMV_DICTIONARY_HPP
#include "tlv++/definition.hpp"
#include "tlv++/codec/dynamic.hpp"
#include "tlv++/schema/definition.hpp"
#include "tlv/builtins/emv/presentation.h"
#include "tlv/builtins/emv/emv_schema.h"

/** @file
 * @brief Immutable EMV dictionary metadata and runtime-selected Value codecs.
 */
namespace tlv {
namespace emv {
/** @brief Program-lifetime EMV structural Schema; dictionary length policy stays separate. */
inline tlv::schema structural_schema() noexcept {
    return detail::schema_access::borrow(&tlv_emv_structure_schema);
}
/** @brief Explicit EMV dictionary context; lookups never fall back to base. */
enum class context {
    base = TLV_EMV_CONTEXT_BASE,                             /**< Ordinary application data. */
    bit = TLV_EMV_CONTEXT_BIT,                               /**< Biometric information template. */
    bht = TLV_EMV_CONTEXT_BHT,                               /**< Biometric header template. */
    bht_format = TLV_EMV_CONTEXT_BHT_FORMAT,                 /**< Biometric header format. */
    bit_group = TLV_EMV_CONTEXT_BIT_GROUP,                   /**< Biometric information group. */
    biometric_counters = TLV_EMV_CONTEXT_BIOMETRIC_COUNTERS, /**< Counters. */
    biometric_attempts = TLV_EMV_CONTEXT_BIOMETRIC_ATTEMPTS, /**< Attempts. */
    biometric_verification = TLV_EMV_CONTEXT_BIOMETRIC_VERIFICATION, /**< Verification. */
    unchanged = TLV_EMV_CONTEXT_COUNT /**< Tag does not introduce a child context. */
};
/** @brief Representation category of the immutable built-in presentation profile. */
enum class value_kind {
    bytes = TLV_EMV_VALUE_BYTES,             /**< Opaque bytes. */
    text = TLV_EMV_VALUE_TEXT,               /**< Opaque text bytes. */
    constructed = TLV_EMV_VALUE_TEMPLATE,    /**< Semantic template. */
    number = TLV_EMV_VALUE_NUMBER,           /**< uint64_t number. */
    flags = TLV_EMV_VALUE_FLAGS,             /**< uint64_t bits. */
    digits = TLV_EMV_VALUE_DIGITS,           /**< NUL-terminated char array. */
    date = TLV_EMV_VALUE_DATE,               /**< emv::date. */
    time = TLV_EMV_VALUE_TIME,               /**< emv::time. */
    account = TLV_EMV_VALUE_ACCOUNT,         /**< emv::account. */
    cryptogram = TLV_EMV_VALUE_CRYPTOGRAM,   /**< emv::cryptogram. */
    biometric = TLV_EMV_VALUE_BIOMETRIC,     /**< emv::biometric. */
    number_list = TLV_EMV_VALUE_NUMBER_LIST, /**< emv::number_list. */
    afl = TLV_EMV_VALUE_AFL,                 /**< emv::afl. */
    cvm_result = TLV_EMV_VALUE_CVM_RESULT,   /**< emv::cvm_result. */
    track2 = TLV_EMV_VALUE_TRACK2,           /**< emv::track2. */
    unknown = TLV_EMV_VALUE_UNKNOWN          /**< No built-in presentation contract. */
};
/** @brief Program-lifetime description of a built-in representation category. */
inline const char* description(value_kind kind) noexcept {
    return tlv_emv_value_kind_description(static_cast<tlv_emv_value_kind_t>(kind));
}
/** @brief Determine an identifier's child context, or context::unchanged. */
inline context child_context(context parent, tlv::tag identifier) noexcept {
    const auto raw = detail::semantic_access::get(identifier);
    return static_cast<context>(
        tlv_emv_child_context(static_cast<tlv_emv_context_t>(parent), &raw));
}
/** @brief Immutable built-in dictionary entry; all returned data has program lifetime. */
class dictionary_entry {
public:
    /** @brief Empty lookup result. */
    dictionary_entry() noexcept = default;
    /** @brief Whether an entry was found in the requested context. */
    explicit operator bool() const noexcept {
        return entry_ != nullptr;
    }
    /** @brief Identifier or an absent identifier for an empty result. */
    tlv::tag tag() const noexcept {
        return entry_ ? detail::semantic_access::borrow(entry_->definition->tag) : tlv::tag{};
    }
    /** @brief Descriptive name, or nullptr for an empty result. */
    const char* name() const noexcept {
        return entry_ ? entry_->definition->name : nullptr;
    }
    /** @brief Optional symbolic field name. */
    const char* symbol() const noexcept {
        return tlv_emv_symbol(entry_);
    }
    /** @brief Inclusive length bounds; default unbounded for an empty result. */
    bounds length() const noexcept {
        return entry_ ? bounds(entry_->schema->min_length, entry_->schema->max_length) : bounds{};
    }
    /** @brief Length step used by the built-in metadata profile, zero when unavailable. */
    size_t length_step() const noexcept {
        return entry_ ? tlv_emv_length_step(entry_) : 0;
    }
    /** @brief Validate a Value length through the shared Schema engine. */
    expected<void, error> validate_length(size_t size) const {
        auto rc = tlv_emv_validate_length(entry_, size);
        if (rc != TLV_OK) return unexpected<error>(error::from_c(rc));
        return {};
    }
    /** @brief Runtime Value codec; absent when the entry retains opaque Value bytes. */
    dynamic_codec codec() const noexcept {
        return detail::codec_access::borrow(entry_ ? entry_->codec : nullptr);
    }
    /** @brief Built-in representation; selecting a codec never examines the enclosing tag. */
    value_kind kind() const noexcept {
        return static_cast<value_kind>(tlv_emv_builtin_value_kind(entry_));
    }

private:
    const tlv_emv_definition_t* entry_ = nullptr;
    explicit dictionary_entry(const tlv_emv_definition_t* value) noexcept : entry_(value) {}
    friend class dictionary;
};
/** @brief Copyable built-in dictionary view; selection and lookup allocate nothing. */
class dictionary {
public:
    /** @brief Select an explicit context; an invalid context yields an empty dictionary. */
    explicit dictionary(context value = context::base) noexcept
        : entries_(tlv_emv_dictionary_for(static_cast<tlv_emv_context_t>(value))) {}
    /** @brief Number of immutable entries. */
    size_t size() const noexcept {
        return entries_ ? entries_->count : 0;
    }
    /** @brief Entry at index, or an empty result if out of range. */
    dictionary_entry at(size_t index) const noexcept {
        return dictionary_entry(index < size() ? &entries_->entries[index] : nullptr);
    }
    /** @brief Find a byte-identical identifier in this context without fallback. */
    dictionary_entry find(tlv::tag identifier) const noexcept {
        const auto raw = detail::semantic_access::get(identifier);
        return dictionary_entry(tlv_emv_dictionary_find(entries_, &raw));
    }

private:
    const tlv_emv_dictionary_t* entries_;
};
} // namespace emv
} // namespace tlv
#endif
