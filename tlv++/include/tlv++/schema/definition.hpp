// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#ifndef OPENTLV_TLVPP_SCHEMA_DEFINITION_HPP
#define OPENTLV_TLVPP_SCHEMA_DEFINITION_HPP
#include "tlv++/types.hpp"
#include "tlv/schema/schema.h"
#include <array>
#include <initializer_list>

/** @file
 * @brief Bounded C++ structural Schema definitions with allocation-free successful construction.
 */
namespace tlv {
/** @brief Required element form. */
enum class schema_kind {
    any = TLV_SCHEMA_ANY,                /**< Either primitive or constructed. */
    primitive = TLV_SCHEMA_PRIMITIVE,    /**< Opaque Value. */
    constructed = TLV_SCHEMA_CONSTRUCTED /**< Nested elements. */
};
/** @brief Relative order of known elements in a parent. */
enum class schema_order {
    any = TLV_SCHEMA_ORDER_ANY,          /**< Any order. */
    sequence = TLV_SCHEMA_ORDER_SEQUENCE /**< Rule-table order. */
};
/** @brief Unknown identifier handling during validation. */
enum class unknown_policy {
    by_schema = TLV_SCHEMA_UNKNOWN_BY_SCHEMA, /**< Use each scope's policy. */
    allow = TLV_SCHEMA_UNKNOWN_ALLOW,         /**< Accept unknown identifiers. */
    reject = TLV_SCHEMA_UNKNOWN_REJECT        /**< Report unknown identifiers. */
};
/** @brief Inclusive bounds for byte lengths or occurrence counts. */
struct bounds {
    size_t minimum; /**< Inclusive minimum. */
    size_t maximum; /**< Inclusive maximum; SIZE_MAX means unbounded. */
    /** @brief Specify an inclusive interval. */
    bounds(size_t minimum = 0, size_t maximum = SIZE_MAX) noexcept
        : minimum(minimum), maximum(maximum) {}
    /** @brief Require exactly count bytes or occurrences. */
    static bounds exactly(size_t count) noexcept {
        return bounds(count, count);
    }
};
/// @cond INTERNAL
namespace detail {
struct schema_access;
}
/// @endcond
/** @brief Borrowed immutable Schema; storage, names and identifier bytes must outlive uses. */
class schema {
public:
    /** @brief Absent child Schema; passing it as a top-level definition is invalid. */
    schema() noexcept = default;

private:
    const tlv_structure_schema_t* descriptor_ = nullptr;
    explicit schema(const tlv_structure_schema_t* value) noexcept : descriptor_(value) {}
    friend struct detail::schema_access;
};
/// @cond INTERNAL
namespace detail {
struct schema_access {
    static const tlv_structure_schema_t* get(schema value) noexcept {
        return value.descriptor_;
    }
    static schema borrow(const tlv_structure_schema_t* value) noexcept {
        return schema(value);
    }
};
} // namespace detail
/// @endcond
/** @brief Declarative rule borrowing identifier bytes, name and optional child Schema. */
struct schema_rule {
    tlv::tag    identifier;  /**< Byte identifier; backing bytes must outlive Schema storage. */
    bounds      length;      /**< Inclusive Value byte-length bounds. */
    bounds      occurrences; /**< Inclusive per-parent occurrence bounds. */
    schema_kind kind;        /**< Required primitive or constructed form. */
    schema children;  /**< Optional borrowed child rules; default leaves children unrestricted. */
    const char* name; /**< Optional borrowed field name used in diagnostics. */
    size_t      length_multiple; /**< Required length divisor; zero disables this restriction. */
    bool        endpoints_only;  /**< Only the two length endpoints are permitted. */
    uint32_t    group;           /**< Alternative group identifier, zero for an independent rule. */
    /**
     * @brief Describe one field without allocating or retaining the rule object itself.
     * @param identifier Borrowed identifier bytes.
     * @param length Inclusive length bounds.
     * @param occurrences Inclusive occurrence bounds, optional and unique by default.
     * @param kind Required form.
     * @param children Child Schema for constructed values, borrowed through validation.
     * @param name Optional borrowed NUL-terminated diagnostic name.
     */
    schema_rule(tlv::tag identifier, bounds length = {}, bounds occurrences = bounds(0, 1),
                schema_kind kind = schema_kind::any, schema children = {},
                const char* name = nullptr) noexcept
        : identifier(identifier), length(length), occurrences(occurrences), kind(kind),
          children(children), name(name), length_multiple(0), endpoints_only(false), group(0) {}
    /**
     * @brief Return a rule copy assigned to an alternative group.
     * @param id Group identifier; zero makes the rule independent.
     * @return Updated value, suitable for chaining in an initializer list since C++11.
     * @note The original rule is unchanged. Copies allocate nothing and retain borrowed lifetimes.
     */
    schema_rule in_group(uint32_t id) const noexcept {
        auto result = *this;
        result.group = id;
        return result;
    }
    /**
     * @brief Return a rule copy requiring Value lengths divisible by a given number.
     * @param divisor Required length divisor; zero disables this restriction.
     * @return Updated value, suitable for chaining in an initializer list since C++11.
     * @note The original rule is unchanged. Copies allocate nothing and retain borrowed lifetimes.
     */
    schema_rule with_length_multiple(size_t divisor) const noexcept {
        auto result = *this;
        result.length_multiple = divisor;
        return result;
    }
    /**
     * @brief Return a rule copy restricting lengths to the inclusive interval's endpoints.
     * @param enabled Whether only the minimum and maximum length are permitted.
     * @return Updated value, suitable for chaining in an initializer list since C++11.
     * @note The original rule is unchanged. Copies allocate nothing and retain borrowed lifetimes.
     */
    schema_rule with_endpoints_only(bool enabled = true) const noexcept {
        auto result = *this;
        result.endpoints_only = enabled;
        return result;
    }
};
/** @brief Alternative group with a shared occurrence constraint. */
struct schema_group {
    uint32_t    id;          /**< Nonzero group identifier referenced by rules. */
    bounds      occurrences; /**< Bounds for all member occurrences combined. */
    const char* name;        /**< Optional borrowed diagnostic name. */
    /** @brief Define a group; identifier and bounds are checked by validation. */
    schema_group(uint32_t id, bounds occurrences, const char* name = nullptr) noexcept
        : id(id), occurrences(occurrences), name(name) {}
};
/**
 * @brief Stationary caller-owned Schema tables with bounded capacity.
 * @tparam Capacity Maximum rule count.
 * @tparam Groups Maximum alternative-group count.
 * @note Successful construction and validation allocate nothing. A capacity error throws
 * std::length_error, whose construction may allocate.
 * @warning Identifier bytes, names and child Schema storage remain borrowed. Keep them
 * and this storage alive and unchanged through all dependent validations.
 */
template <size_t Capacity, size_t Groups = 0> class schema_storage {
public:
    /**
     * @brief Copy rule values into bounded storage and bind their canonical descriptors.
     * @param rules Rules copied during construction; borrowed payloads retain their lifetime.
     * @param order Ordering policy.
     * @param allow_unknown Whether unmatched identifiers are allowed in this scope.
     * @param groups Alternative-group definitions.
     * @throws std::length_error If either initializer list exceeds its declared capacity.
     * Constructing this exception may allocate; successful construction does not allocate.
     */
    schema_storage(std::initializer_list<schema_rule> rules, schema_order order = schema_order::any,
                   bool allow_unknown = false, std::initializer_list<schema_group> groups = {}) {
        if (rules.size() > Capacity || groups.size() > Groups)
            throw std::length_error("Schema storage capacity exceeded");
        size_t i = 0;
        for (const auto& rule : rules) {
            fields_[i] = {detail::semantic_access::get(rule.identifier),
                          rule.length.minimum,
                          rule.length.maximum,
                          rule.endpoints_only ? uint32_t(TLV_SCHEMA_LENGTH_ENDPOINTS) : 0u,
                          rule.name,
                          rule.length_multiple};
            rules_[i] = {&fields_[i],
                         rule.occurrences.minimum,
                         rule.occurrences.maximum,
                         static_cast<tlv_schema_kind_t>(rule.kind),
                         detail::schema_access::get(rule.children),
                         rule.group};
            ++i;
        }
        i = 0;
        for (const auto& group : groups)
            groups_[i++] = {group.id, group.occurrences.minimum, group.occurrences.maximum,
                            group.name};
        descriptor_ = {rules_.data(),  rules.size(),  allow_unknown ? 1 : 0,
                       groups_.data(), groups.size(), static_cast<tlv_schema_order_t>(order)};
    }
    /** @brief Storage is stationary because views retain addresses into it. */
    schema_storage(const schema_storage&) = delete;
    /** @brief Do not replace storage borrowed by a Schema. */
    schema_storage& operator=(const schema_storage&) = delete;
    /** @brief Borrow these tables without allocation; storage must outlive the view. */
    schema view() const& noexcept {
        return detail::schema_access::borrow(&descriptor_);
    }
    /** @brief Reject borrowing a temporary owner. */
    schema view() const&& = delete;

private:
    std::array<tlv_schema_entry_t, Capacity>   fields_{};
    std::array<tlv_structure_rule_t, Capacity> rules_{};
    std::array<tlv_structure_group_t, Groups>  groups_{};
    tlv_structure_schema_t                     descriptor_{};
};
} // namespace tlv
#endif
