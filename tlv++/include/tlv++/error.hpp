// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#ifndef OPENTLV_TLVPP_ERROR_HPP
#define OPENTLV_TLVPP_ERROR_HPP
#include "tlv/error.h"
#include "tlv/diagnostic.h"
#include <cstddef>

/** @file
 * @brief Allocation-free C++ operation status and error context.
 */
namespace tlv {
class tag;
/// @cond INTERNAL
namespace detail {
struct error_access;
}
/// @endcond
/** @brief Canonical operation outcomes, independent of native enum types. */
enum class errc {
    ok = TLV_OK,                                     /**< Operation completed. */
    buffer_too_short = TLV_ERR_BUFFER_TOO_SHORT,     /**< Insufficient input or output. */
    invalid_length = TLV_ERR_INVALID_LENGTH,         /**< Invalid wire length. */
    null_argument = TLV_ERR_NULL_ARG,                /**< Missing required storage. */
    out_of_memory = TLV_ERR_OUT_OF_MEMORY,           /**< Allocation failed. */
    end_of_input = TLV_ERR_END_OF_BUFFER,            /**< Final input exhausted. */
    invalid_tag = TLV_ERR_INVALID_TAG,               /**< Invalid identifier. */
    visitor = TLV_ERR_VISITOR,                       /**< Visitor requested failure. */
    limit = TLV_ERR_LIMIT,                           /**< Configured limit exceeded. */
    schema = TLV_ERR_SCHEMA,                         /**< Schema violation. */
    invalid_argument = TLV_ERR_INVALID_ARG,          /**< Invalid argument. */
    invalid_tag_size = TLV_ERR_INVALID_TAG_SIZE,     /**< Invalid identifier width. */
    invalid_byte_order = TLV_ERR_INVALID_BYTE_ORDER, /**< Unsupported byte order. */
    overflow = TLV_ERR_OVERFLOW,                     /**< Numeric overflow. */
    invalid_value = TLV_ERR_INVALID_VALUE,           /**< Invalid semantic value. */
    unsupported_type = TLV_ERR_UNSUPPORTED_TYPE,     /**< Unsupported value type. */
    missing_field = TLV_ERR_SCHEMA_MISSING,          /**< Required field is absent. */
    native_size = TLV_ERR_NATIVE_SIZE,               /**< Logical size exceeds address space. */
    need_more_data = TLV_NEED_MORE_DATA              /**< Non-final input needs continuation. */
};
/** @brief Name an operation status using immutable program-lifetime text; never allocates. */
inline const char* message(errc code) noexcept {
    return tlv_strerror(static_cast<tlv_result_t>(code));
}
/** @brief Stable symbolic spelling of a canonical status, for logs and serialized diagnostics. */
inline const char* name(errc code) noexcept {
    switch (code) {
        case errc::ok: return "TLV_OK";
        case errc::buffer_too_short: return "TLV_ERR_BUFFER_TOO_SHORT";
        case errc::invalid_length: return "TLV_ERR_INVALID_LENGTH";
        case errc::null_argument: return "TLV_ERR_NULL_ARG";
        case errc::out_of_memory: return "TLV_ERR_OUT_OF_MEMORY";
        case errc::end_of_input: return "TLV_ERR_END_OF_BUFFER";
        case errc::invalid_tag: return "TLV_ERR_INVALID_TAG";
        case errc::visitor: return "TLV_ERR_VISITOR";
        case errc::limit: return "TLV_ERR_LIMIT";
        case errc::schema: return "TLV_ERR_SCHEMA";
        case errc::invalid_argument: return "TLV_ERR_INVALID_ARG";
        case errc::invalid_tag_size: return "TLV_ERR_INVALID_TAG_SIZE";
        case errc::invalid_byte_order: return "TLV_ERR_INVALID_BYTE_ORDER";
        case errc::overflow: return "TLV_ERR_OVERFLOW";
        case errc::invalid_value: return "TLV_ERR_INVALID_VALUE";
        case errc::unsupported_type: return "TLV_ERR_UNSUPPORTED_TYPE";
        case errc::missing_field: return "TLV_ERR_SCHEMA_MISSING";
        case errc::native_size: return "TLV_ERR_NATIVE_SIZE";
        case errc::need_more_data: return "TLV_NEED_MORE_DATA";
    }
    return "TLV_ERR_UNKNOWN";
}
/** @brief Subsystem that produced an error. */
enum class operation {
    unspecified, /**< No operation context was supplied. */
    format,      /**< Wire Format operation. */
    reader,      /**< Sequential or tree reading. */
    writer,      /**< Sequential or tree writing. */
    codec,       /**< Value conversion. */
    schema,      /**< Structural validation. */
    document,    /**< Owning tree operation. */
    query        /**< Query compilation or execution. */
};
/** @brief Common diagnostic severity across all C++ operations. */
enum class severity {
    error = TLV_DIAGNOSTIC_SEVERITY_ERROR,     /**< Operation failed. */
    warning = TLV_DIAGNOSTIC_SEVERITY_WARNING, /**< Recoverable observation. */
    info = TLV_DIAGNOSTIC_SEVERITY_INFO        /**< Informational observation. */
};
/**
 * @brief Allocation-free operation error with optional absolute byte offset.
 *
 * Text is borrowed, normally from immutable program-lifetime library strings.
 * Custom descriptions must outlive every error copy. Numeric context is copied.
 */
struct error {
    /** @brief Native status retained for transitional interoperability. */
    tlv_result_t code;
    /** @brief Borrowed NUL-terminated description, never null for library errors. */
    const char* message() const noexcept {
        return message_;
    }
    /** @brief Construct an error with a program-lifetime canonical description. */
    explicit error(errc value, operation stage = operation::unspecified) noexcept
        : code(static_cast<tlv_result_t>(value)), message_(tlv::message(value)), stage_(stage) {}
    /** @brief Construct an interoperability error with borrowed description. */
    error(tlv_result_t value, const char* description) noexcept
        : code(value), message_(description ? description : tlv_strerror(value)) {}
    /** @brief Translate a native code without allocating. */
    static error from_c(tlv_result_t value) noexcept {
        return error(static_cast<errc>(value));
    }
    /** @brief Canonical C++ status, including distinct EOF and resumable input. */
    errc status() const noexcept {
        return static_cast<errc>(code);
    }
    /** @brief Subsystem responsible for this failure. */
    operation stage() const noexcept {
        return stage_;
    }
    /** @brief Severity of this diagnostic; operation errors default to error. */
    tlv::severity severity() const noexcept {
        return severity_;
    }
    /** @brief Whether offset() contains a known location. */
    bool has_offset() const noexcept {
        return located_;
    }
    /** @brief Absolute byte offset, valid only when has_offset() is true. */
    std::size_t offset() const noexcept {
        return offset_;
    }
    /** @brief Whether tag() identifies the failing element; identifier bytes remain borrowed. */
    bool has_tag() const noexcept {
        return has_tag_;
    }
    /** @brief Borrow the failing identifier, or an absent identifier when unavailable. */
    tlv::tag tag() const noexcept;
    /** @brief Number of enclosing identifiers copied into this error. */
    size_t depth() const noexcept {
        return path_.length;
    }
    /** @brief Borrow an enclosing identifier; out-of-range indices return an absent identifier. */
    tlv::tag ancestor(size_t index) const noexcept;
    /** @brief Optional borrowed expected constraint description. */
    const char* expected() const noexcept {
        return expected_;
    }
    /** @brief Optional borrowed observed-value description. */
    const char* actual() const noexcept {
        return actual_;
    }
    /** @brief Return a copy annotated with a subsystem, without inventing a location. */
    error during(operation stage) const noexcept {
        auto copy = *this;
        copy.stage_ = stage;
        return copy;
    }
    /** @brief Return an enriched copy without modifying the original or allocating. */
    error at(std::size_t offset, operation stage) const noexcept {
        error copy = *this;
        copy.offset_ = offset;
        copy.located_ = true;
        copy.stage_ = stage;
        return copy;
    }

private:
    const char*           message_;
    operation             stage_ = operation::unspecified;
    std::size_t           offset_ = 0;
    bool                  located_ = false;
    tlv::severity         severity_ = tlv::severity::error;
    tlv_tag_t             tag_{};
    tlv_diagnostic_path_t path_{};
    bool                  has_tag_ = false;
    const char*           expected_ = nullptr;
    const char*           actual_ = nullptr;
    friend struct detail::error_access;
};
/** @brief Project an ordinary error into the common diagnostic contract without allocation. */
inline error to_error(const error& value) noexcept {
    return value;
}
/** @brief Project a specialized failure while retaining its detailed original error object.
 * @tparam Failure Specialized error exposing failure() returning tlv::error.
 * @param value Error from Format, Writer, typed fields, Query or a traversal exception.
 * @return Allocation-free common status, description and available source context.
 */
template <typename Failure> inline error to_error(const Failure& value) noexcept {
    return value.failure();
}
/// @cond INTERNAL
namespace detail {
struct error_access {
    static error diagnostic(const tlv_diagnostic_t& value, operation stage,
                            const tlv_tag_t*             tag = nullptr,
                            const tlv_diagnostic_path_t* path = nullptr) noexcept {
        error result(static_cast<errc>(value.code), stage);
        if (value.has_offset) result = result.at(value.offset, stage);
        if (path)
            result.path_ = *path;
        else if (value.path)
            result.path_ = *value.path;
        result.severity_ = static_cast<tlv::severity>(value.severity);
        if (tag) {
            result.tag_ = *tag;
            result.has_tag_ = true;
        }
        result.expected_ = value.expected;
        result.actual_ = value.actual;
        return result;
    }
};
} // namespace detail
/// @endcond
} // namespace tlv
#endif
