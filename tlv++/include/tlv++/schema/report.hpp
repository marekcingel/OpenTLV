// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#ifndef OPENTLV_TLVPP_SCHEMA_REPORT_HPP
#define OPENTLV_TLVPP_SCHEMA_REPORT_HPP
#include "tlv++/schema/definition.hpp"
#include "tlv++/format.hpp"
#include "tlv++/diagnostic.hpp"

/** @file
 * @brief Bounded validation reports with borrowed C++ diagnostic views.
 */
namespace tlv {
/** @brief Category of structural Schema violation. */
enum class schema_issue {
    missing = TLV_SCHEMA_ISSUE_MISSING,       /**< Required field or group absent. */
    duplicate = TLV_SCHEMA_ISSUE_DUPLICATE,   /**< Too many occurrences. */
    unexpected = TLV_SCHEMA_ISSUE_UNEXPECTED, /**< Unknown or forbidden identifier. */
    kind = TLV_SCHEMA_ISSUE_KIND,             /**< Primitive/constructed mismatch. */
    length = TLV_SCHEMA_ISSUE_LENGTH,         /**< Invalid Value length. */
    order = TLV_SCHEMA_ISSUE_ORDER,           /**< Invalid sibling order. */
    assertion = TLV_SCHEMA_ISSUE_ASSERTION    /**< Query assertion failed. */
};
/** @brief Program-lifetime name of a Schema violation category. */
inline const char* message(schema_issue kind) noexcept {
    return tlv_schema_issue_kind_string(static_cast<tlv_schema_issue_kind_t>(kind));
}
/**
 * @brief Copyable violation detail; identifiers and field names retain their borrowed lifetime.
 * @note Copies do not allocate or retain the report object.
 */
class validation_issue {
public:
    /** @brief Empty diagnostic, for explicitly optional report storage. */
    validation_issue() noexcept : raw_{} {}
    /** @brief Violation category. */
    schema_issue kind() const noexcept {
        return static_cast<schema_issue>(raw_.kind);
    }
    /** @brief Canonical status and absolute wire offset. */
    tlv::error error() const noexcept {
        return detail::error_access::diagnostic(raw_.diagnostic, operation::schema, &raw_.tag,
                                                &raw_.path);
    }
    /** @brief Affected identifier, borrowed from input, Format or Schema. */
    tlv::tag tag() const noexcept {
        return detail::semantic_access::borrow(raw_.tag);
    }
    /** @brief Optional borrowed field or group name, or nullptr. */
    const char* field() const noexcept {
        return raw_.field;
    }
    /** @brief Whether this violation concerns an alternative group. */
    bool is_group() const noexcept {
        return raw_.is_group != 0;
    }
    /** @brief Number of retained outermost enclosing identifiers. */
    size_t depth() const noexcept {
        return raw_.path.length;
    }
    /** @brief Number of innermost enclosing identifiers omitted after the retained outer prefix. */
    size_t omitted_depth() const noexcept {
        return raw_.path.omitted;
    }
    /** @brief Borrow an enclosing identifier; returns absent when index is out of range. */
    tlv::tag ancestor(size_t index) const noexcept {
        return index < depth() ? detail::semantic_access::borrow(raw_.path.tags[index])
                               : tlv::tag{};
    }
    /** @brief Whether occurrence details are available. */
    bool has_occurrences() const noexcept {
        return raw_.has_occurs != 0;
    }
    /** @brief Expected occurrence bounds, valid when has_occurrences(). */
    bounds expected_occurrences() const noexcept {
        return {raw_.min_occurs, raw_.max_occurs};
    }
    /** @brief Observed occurrence count, valid when has_occurrences(). */
    size_t occurrences() const noexcept {
        return raw_.occurs;
    }
    /** @brief Common diagnostic metadata; its external strings remain borrowed. */
    tlv::diagnostic diagnostic() const noexcept {
        return raw_.diagnostic;
    }
    /** @brief Copied enclosing path; identifier bytes remain borrowed. */
    diagnostic_path path() const noexcept {
        return raw_.path;
    }
    /** @brief Whether length constraint details are available. */
    bool has_length() const noexcept {
        return raw_.has_length != 0;
    }
    /** @brief Inclusive expected length bounds, valid when has_length(). */
    bounds expected_length() const noexcept {
        return {raw_.min_length, raw_.max_length};
    }
    /** @brief Observed Value length, valid when has_length(). */
    size_t length() const noexcept {
        return raw_.actual_length;
    }
    /** @brief Required length multiple, zero for unrestricted. */
    size_t length_multiple() const noexcept {
        return raw_.length_multiple;
    }
    /** @brief Whether only the two length bounds are permitted. */
    bool length_endpoints_only() const noexcept {
        return (raw_.length_flags & TLV_SCHEMA_LENGTH_ENDPOINTS) != 0;
    }
    /** @brief Whether element form constraint details are available. */
    bool has_form() const noexcept {
        return raw_.has_form != 0;
    }
    /** @brief Required element form, valid when has_form(). */
    schema_kind expected_form() const noexcept {
        return static_cast<schema_kind>(raw_.expected_form);
    }
    /** @brief Whether the observed element was constructed, valid when has_form(). */
    bool constructed() const noexcept {
        return raw_.actual_constructed != 0;
    }

private:
    explicit validation_issue(tlv_schema_diagnostic_t raw) noexcept : raw_(raw) {
        raw_.diagnostic.path = nullptr;
    }
    tlv_schema_diagnostic_t raw_;
    template <size_t> friend class validation_report;
};
/**
 * @brief Caller-owned report storage retaining the first Capacity Schema violations.
 * @tparam Capacity Maximum retained violation count, including zero for counting only.
 * @warning Retained identifiers and names borrow input, Format and Schema storage.
 * Validation replaces the prior report; it never allocates.
 * @note Storage grows linearly with Capacity: each record contains a full inline
 * diagnostic path. Choose Capacity and storage placement for the application's
 * memory budget; Capacity zero counts violations without retaining records.
 */
template <size_t Capacity> class validation_report {
public:
    /**
     * @brief Validate framing and collect structural violations through the canonical engine.
     * @param input Immutable borrowed wire bytes.
     * @param format Readable borrowed Format.
     * @param definition Immutable borrowed Schema.
     * @param unknown Override for unknown identifiers.
     * @param max_depth Maximum nesting depth.
     * @param max_elements Maximum element count.
     * @return Total violations (possibly greater than capacity), or a wire/argument failure.
     * @note A Schema violation is report data, not a failed report operation.
     */
    expected<size_t, error> validate(bytes input, tlv::format format, schema definition,
                                     unknown_policy unknown = unknown_policy::by_schema,
                                     size_t         max_depth = TLV_SCHEMA_MAX_DEPTH,
                                     size_t         max_elements = SIZE_MAX) {
        tlv_schema_diagnostic_report_t report{storage_.data(), Capacity, 0};
        size_t                         offset = 0;
        const auto                     rc = tlv_schema_validate_all_diag(
            reinterpret_cast<const uint8_t*>(input.data()), input.size(),
            &detail::format_access::get(format), detail::schema_access::get(definition), max_depth,
            max_elements, static_cast<tlv_schema_unknown_policy_t>(unknown), &report, &offset);
        total_ = report.count;
        if (rc != TLV_OK && rc != TLV_ERR_SCHEMA)
            return unexpected<error>(error::from_c(rc).at(offset, operation::schema));
        return total_;
    }
    /** @brief Number of retained violations. */
    size_t size() const noexcept {
        return total_ < Capacity ? total_ : Capacity;
    }
    /** @brief Total violations, including those not retained. */
    size_t total() const noexcept {
        return total_;
    }
    /** @brief Whether some violations exceeded the fixed storage capacity. */
    bool truncated() const noexcept {
        return total_ > Capacity;
    }
    /** @brief Copy retained detail; throws std::out_of_range for an unavailable index. */
    validation_issue at(size_t index) const {
        if (index >= size()) throw std::out_of_range("Schema report index");
        return validation_issue(storage_[index]);
    }

private:
    std::array<tlv_schema_diagnostic_t, Capacity> storage_{};
    size_t                                        total_ = 0;
};
} // namespace tlv
#endif
