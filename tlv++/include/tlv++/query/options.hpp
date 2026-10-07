// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel
#ifndef OPENTLV_TLVPP_QUERY_OPTIONS_HPP
#define OPENTLV_TLVPP_QUERY_OPTIONS_HPP
#include "tlv++/format.hpp"
#include "tlv/query/adapters.h"
#include <vector>

/** @file
 * @brief C++ Query environment and variable declarations.
 */
namespace tlv {
/** @brief Category of a Query expression or declared variable. */
enum class query_type {
    nodes = TLV_QUERY_RESULT_NODES,     /**< Ordered node sequence. */
    boolean = TLV_QUERY_RESULT_BOOL,    /**< Boolean scalar. */
    integer = TLV_QUERY_RESULT_INTEGER, /**< Signed integer. */
    bytes = TLV_QUERY_RESULT_BYTES,     /**< Byte scalar. */
    string = TLV_QUERY_RESULT_STRING    /**< UTF-8 scalar. */
};
/** @brief Whole-expression backend requirement. */
enum class query_level {
    node = TLV_QUERY_S0,     /**< Decisions at node publication. */
    scope = TLV_QUERY_S1,    /**< Bounded scope summaries. */
    retained = TLV_QUERY_S2, /**< Input-dependent candidate storage. */
    document = TLV_QUERY_D   /**< Document navigation. */
};
/// @cond INTERNAL
namespace detail {
struct query_options_access;
}
/// @endcond
/** @brief Borrowed compiler configuration; default construction selects canonical defaults.
 * @warning The owner, declaration names and providers must outlive compilation.
 */
class query_settings {
public:
    /** @brief Select canonical defaults without storage or allocation. */
    query_settings(std::nullptr_t = nullptr) noexcept {}

private:
    const tlv_query_compile_options_t* raw_ = nullptr;
    explicit query_settings(const tlv_query_compile_options_t* value) noexcept : raw_(value) {}
    friend class query_options;
    friend struct detail::query_options_access;
};
/** @brief Borrowed runtime capabilities; an empty view selects no external providers.
 * @warning Environment and provider state must remain alive and immutable through execution.
 */
class query_capabilities {
public:
    /** @brief Select an absent external environment without allocation. */
    query_capabilities(std::nullptr_t = nullptr) noexcept {}
    /** @brief Whether an external environment is configured. */
    explicit operator bool() const noexcept {
        return raw_ != nullptr;
    }

private:
    const tlv_query_environment_t* raw_ = nullptr;
    explicit query_capabilities(const tlv_query_environment_t* value) noexcept : raw_(value) {}
    friend class query_environment;
    friend struct detail::query_options_access;
};
/** @brief Stationary Query capabilities borrowing immutable Format and provider contexts.
 * @note With Codec enabled, construction adds canonical NUM, BCD and TEXT providers. Provider
 * storage grows only when configuring the environment, never during execution.
 * @warning Finish configuration before compiling; this owner and every borrowed
 * provider context must outlive compiled programs and executions using them.
 */
class query_environment {
public:
    /** @brief Select a borrowed Format and the standard generic Value providers. */
    explicit query_environment(tlv::format format) {
        raw_.format = &detail::format_access::get(format);
#if OPENTLV_CODEC
        size_t      count = 0;
        const auto* hooks = tlv_query_builtin_hooks(&count);
        hooks_.assign(hooks, hooks + count);
#endif
        refresh();
    }
    /** @brief Environments remain stationary because programs borrow their capabilities. */
    query_environment(const query_environment&) = delete;
    /** @brief Do not replace an environment borrowed by existing programs. */
    query_environment& operator=(const query_environment&) = delete;
    /** @brief Borrow configured capabilities; this stationary owner must outlive every use. */
    query_capabilities view() const& noexcept {
        return query_capabilities(&raw_);
    }
    /** @brief Reject borrowing capabilities from a temporary environment. */
    query_capabilities view() const&& = delete;

private:
    tlv_query_environment_t       raw_{};
    std::vector<tlv_query_hook_t> hooks_;
    void                          refresh() {
        raw_.hooks = hooks_.data();
        raw_.hook_count = hooks_.size();
    }
    friend struct detail::query_options_access;
};
/** @brief Stationary owning variable-declaration table with borrowed names and capabilities.
 * @note Adding declarations may allocate. Names and environment must remain alive
 * and unchanged throughout compilation. The canonical compiler validates types.
 */
class query_options {
public:
    /** @brief Initialize canonical compiler defaults and an optional borrowed environment. */
    explicit query_options(const query_environment* environment = nullptr);
    /** @brief Keep the declaration table at a stable address. */
    query_options(const query_options&) = delete;
    /** @brief Do not replace storage borrowed during compilation. */
    query_options& operator=(const query_options&) = delete;
    /** @brief Borrow declarations and compiler settings for a compilation operation. */
    query_settings view() const& noexcept {
        return query_settings(&raw_);
    }
    /** @brief Reject borrowing settings from a temporary owner. */
    query_settings view() const&& = delete;
    /** @brief Declare a borrowed NUL-terminated variable name and required value type. */
    void declare(const char* name, query_type type) {
        variables_.push_back({name, static_cast<tlv_query_result_kind_t>(type)});
        raw_.variables = variables_.data();
        raw_.variable_count = variables_.size();
    }

private:
    tlv_query_compile_options_t       raw_{};
    std::vector<tlv_query_variable_t> variables_;
    friend struct detail::query_options_access;
};
/// @cond INTERNAL
namespace detail {
struct query_options_access {
    static const tlv_query_compile_options_t* get(query_settings value) {
        return value.raw_;
    }
    static const tlv_query_environment_t* get(query_capabilities value) {
        return value.raw_;
    }
    static query_settings borrow(const tlv_query_compile_options_t* value) {
        return query_settings(value);
    }
    static query_capabilities borrow(const tlv_query_environment_t* value) {
        return query_capabilities(value);
    }
    static const tlv_query_environment_t* get(const query_environment& value) {
        return &value.raw_;
    }
    static const tlv_query_compile_options_t* get(const query_options& value) {
        return &value.raw_;
    }
    static void tags(query_environment& value, const tlv_query_tag_adapter_t* provider) {
        value.raw_.tags = provider;
    }
    static void hook(query_environment& value, const tlv_query_hook_t& hook) {
        value.hooks_.push_back(hook);
        value.refresh();
    }
    static void resolver(query_options& value, tlv_query_resolve_t resolve,
                         const void* context = nullptr) {
        value.raw_.resolve = resolve;
        value.raw_.resolve_context = context;
    }
};
} // namespace detail
/// @endcond
inline query_options::query_options(const query_environment* environment) {
    tlv_query_compile_options_init(&raw_);
    raw_.environment = environment ? detail::query_options_access::get(*environment) : nullptr;
}
} // namespace tlv
#endif
