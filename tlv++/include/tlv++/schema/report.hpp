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
        return static_cast<schema_issue>(raw_.detail.kind);
    }
    /** @brief Canonical status and absolute wire offset. */
    tlv::error error() const noexcept {
        return detail::error_access::schema(raw_);
    }
    /** @brief Affected identifier, borrowed from input, Format or Schema. */
    tlv::tag tag() const noexcept {
        return detail::semantic_access::borrow(raw_.detail.tag);
    }
    /** @brief Optional borrowed field or group name, or nullptr. */
    const char* field() const noexcept {
        return raw_.detail.field;
    }
    /** @brief Whether this violation concerns an alternative group. */
    bool is_group() const noexcept {
        return raw_.detail.is_group != 0;
    }
    /** @brief Number of retained outermost enclosing identifiers. */
    size_t depth() const noexcept {
        return raw_.diagnostic.path.length;
    }
    /** @brief Number of innermost enclosing identifiers omitted after the retained outer prefix. */
    size_t omitted_depth() const noexcept {
        return raw_.diagnostic.path.omitted;
    }
    /** @brief Borrow an enclosing identifier; returns absent when index is out of range. */
    tlv::tag ancestor(size_t index) const noexcept {
        return index < depth() ? detail::semantic_access::borrow(raw_.diagnostic.path.tags[index])
                               : tlv::tag{};
    }
    /** @brief Whether occurrence details are available. */
    bool has_occurrences() const noexcept {
        return raw_.detail.has_occurs != 0;
    }
    /** @brief Expected occurrence bounds, valid when has_occurrences(). */
    bounds expected_occurrences() const noexcept {
        return {raw_.detail.min_occurs, raw_.detail.max_occurs};
    }
    /** @brief Observed occurrence count, valid when has_occurrences(). */
    size_t occurrences() const noexcept {
        return raw_.detail.occurs;
    }
    /** @brief Common diagnostic metadata; its external strings remain borrowed. */
    tlv::diagnostic diagnostic() const noexcept {
        return raw_.diagnostic;
    }
    /** @brief Copied enclosing path; identifier bytes remain borrowed. */
    diagnostic_path path() const noexcept {
        return raw_.diagnostic.path;
    }
    /** @brief Whether length constraint details are available. */
    bool has_length() const noexcept {
        return raw_.detail.has_length != 0;
    }
    /** @brief Inclusive expected length bounds, valid when has_length(). */
    bounds expected_length() const noexcept {
        return {raw_.detail.min_length, raw_.detail.max_length};
    }
    /** @brief Observed Value length, valid when has_length(). */
    size_t length() const noexcept {
        return raw_.detail.actual_length;
    }
    /** @brief Required length multiple, zero for unrestricted. */
    size_t length_multiple() const noexcept {
        return raw_.detail.length_multiple;
    }
    /** @brief Whether only the two length bounds are permitted. */
    bool length_endpoints_only() const noexcept {
        return (raw_.detail.length_flags & TLV_SCHEMA_LENGTH_ENDPOINTS) != 0;
    }
    /** @brief Whether element form constraint details are available. */
    bool has_form() const noexcept {
        return raw_.detail.has_form != 0;
    }
    /** @brief Required element form, valid when has_form(). */
    schema_kind expected_form() const noexcept {
        return static_cast<schema_kind>(raw_.detail.expected_form);
    }
    /** @brief Whether the observed element was constructed, valid when has_form(). */
    bool constructed() const noexcept {
        return raw_.detail.actual_constructed != 0;
    }

private:
    explicit validation_issue(tlv_schema_diagnostic_t raw) noexcept : raw_(raw) {}
    tlv_schema_diagnostic_t raw_;
    template <size_t> friend class validation_report;
};
/**
 * @brief Borrowed Schema whose definition was checked once, for repeated validation.
 *
 * Validation through this handle runs the same engine as validation with the
 * plain `tlv::schema` but skips the per-call definition check. Runtime limits are
 * still checked on every call. Copies share the same borrowed Schema.
 * @warning The Schema storage must stay alive and unchanged while the handle is
 * used; mutation is not detected. Prepare again after changing the definition.
 */
class checked_schema {
public:
    /**
     * @brief Check a Schema definition once.
     * @param definition Immutable borrowed Schema.
     * @return The prepared handle, or the definition failure of tlv_schema_prepare().
     */
    static expected<checked_schema, error> prepare(schema definition) {
        checked_schema          result;
        tlv_schema_diagnostic_t diagnostic{};
        if (tlv_schema_prepare(&result.raw_, detail::schema_access::get(definition), &diagnostic) !=
            TLV_OK)
            return unexpected<error>(detail::error_access::schema(diagnostic));
        return result;
    }
    /** @brief The checked borrowed Schema. */
    schema definition() const noexcept {
        return detail::schema_access::borrow(raw_.schema);
    }
    /** @brief Native handle for the `_checked` C functions. */
    const tlv_schema_checked_t& native() const noexcept {
        return raw_;
    }

private:
    checked_schema() noexcept = default;
    tlv_schema_checked_t raw_{};
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
        tlv_schema_diagnostic_t        diagnostic{};
        const auto                     rc = tlv_schema_validate_all_diag(
            reinterpret_cast<const uint8_t*>(input.data()), input.size(),
            &detail::format_access::get(format), detail::schema_access::get(definition), max_depth,
            max_elements, static_cast<tlv_schema_unknown_policy_t>(unknown), &report, &diagnostic);
        total_ = report.count;
        if (rc != TLV_OK && rc != TLV_ERR_SCHEMA)
            return unexpected<error>(detail::error_access::schema(diagnostic));
        return total_;
    }
    /**
     * @brief Collect structural violations against a prepared Schema without rechecking it.
     * @param input Immutable borrowed wire bytes.
     * @param format Readable borrowed Format.
     * @param definition Prepared Schema; its storage must be unchanged since preparation.
     * @param unknown Override for unknown identifiers.
     * @param max_depth Maximum nesting depth.
     * @param max_elements Maximum element count.
     * @return Total violations (possibly greater than capacity), or a wire/argument failure.
     */
    expected<size_t, error> validate(bytes input, tlv::format format,
                                     const checked_schema& definition,
                                     unknown_policy        unknown = unknown_policy::by_schema,
                                     size_t                max_depth = TLV_SCHEMA_MAX_DEPTH,
                                     size_t                max_elements = SIZE_MAX) {
        tlv_schema_diagnostic_report_t report{storage_.data(), Capacity, 0};
        tlv_schema_diagnostic_t        diagnostic{};
        const auto                     rc = tlv_schema_validate_all_checked(
            &definition.native(), reinterpret_cast<const uint8_t*>(input.data()), input.size(),
            &detail::format_access::get(format), max_depth, max_elements,
            static_cast<tlv_schema_unknown_policy_t>(unknown), &report, &diagnostic);
        total_ = report.count;
        if (rc != TLV_OK && rc != TLV_ERR_SCHEMA) {
            diagnostic.diagnostic.code = rc;
            return unexpected<error>(detail::error_access::schema(diagnostic));
        }
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
