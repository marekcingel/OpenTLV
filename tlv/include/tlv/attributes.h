#ifndef OPENTLV_ATTRIBUTES_H
#define OPENTLV_ATTRIBUTES_H

#include "tlv/compiler.h"

/**
 * @file
 * @ingroup core
 * @brief Portable declaration attributes built on tlv/compiler.h.
 *
 * Each macro expands to the strongest attribute the active language standard
 * and compiler support, using the capabilities detected by tlv/compiler.h,
 * and degrades to nothing (or, for #TLV_FALLTHROUGH, to no statement) where
 * none apply, including the C99 baseline. A declaration written once, for
 * example `TLV_NODISCARD tlv_result_t tlv_reader_next(...)`, therefore keeps
 * the same API and ABI on every supported toolchain while newer ones gain
 * stronger compile-time diagnostics. This header defines no functions or
 * types, only preprocessor macros, so it needs no `extern "C"` guard and is
 * safe to include from both C and C++ translation units.
 */

/** @addtogroup core
 * @{
 */

/* Internal: nonzero when the standard [[...]] attribute syntax used below is
 * available (C++17 or newer, or C23; TLV_HAS_C23 is always 0 when compiling
 * as C++, so no separate !defined(__cplusplus) guard is needed here).
 * Undefined again once the last macro that reads it is defined; excluded
 * from the generated reference via EXCLUDE_SYMBOLS. */
#if (defined(__cplusplus) && __cplusplus >= 201703L) || TLV_HAS_C23
#define TLV_ATTRIBUTES_HAS_STD_ATTR 1
#else
#define TLV_ATTRIBUTES_HAS_STD_ATTR 0
#endif

/**
 * @brief Marks a function whose return value must not be silently discarded.
 *
 * Expands to the standard `[[nodiscard]]` attribute in C++17 or newer or in
 * C23, to `__attribute__((warn_unused_result))` on compilers that recognize
 * it (GCC, Clang), and to nothing otherwise, including the C99 baseline. The
 * annotated declaration's signature, linkage and ABI are unchanged in every
 * case.
 */
#if TLV_ATTRIBUTES_HAS_STD_ATTR
#define TLV_NODISCARD [[nodiscard]]
#elif TLV_HAS_ATTRIBUTE(warn_unused_result)
#define TLV_NODISCARD __attribute__((warn_unused_result))
#else
#define TLV_NODISCARD
#endif

/**
 * @brief Marks a declaration that may be intentionally unused.
 *
 * Expands to the standard `[[maybe_unused]]` attribute in C++17 or newer or
 * in C23, to `__attribute__((unused))` on compilers that recognize it (GCC,
 * Clang), and to nothing otherwise, including the C99 baseline.
 */
#if TLV_ATTRIBUTES_HAS_STD_ATTR
#define TLV_MAYBE_UNUSED [[maybe_unused]]
#elif TLV_HAS_ATTRIBUTE(unused)
#define TLV_MAYBE_UNUSED __attribute__((unused))
#else
#define TLV_MAYBE_UNUSED
#endif

/**
 * @brief Marks a declaration as deprecated, with a message naming the
 * replacement.
 *
 * Named `TLV_DEPRECATED_MSG` rather than `TLV_DEPRECATED` because the latter
 * is already defined, without a message, by CMake's `GenerateExportHeader` in
 * the generated tlv/export.h that most public headers include.
 *
 * `message` must be a string literal. Expands to the standard
 * `[[deprecated(message)]]` attribute in C++14 or newer or in C23, to
 * `__attribute__((deprecated(message)))` on compilers that recognize it (GCC,
 * Clang), to `__declspec(deprecated(message))` on compilers that recognize
 * that instead (MSVC, clang-cl), and to nothing otherwise, including the C99
 * baseline.
 */
#if (defined(__cplusplus) && __cplusplus >= 201402L) || TLV_HAS_C23
#define TLV_DEPRECATED_MSG(message) [[deprecated(message)]]
#elif TLV_HAS_ATTRIBUTE(deprecated)
#define TLV_DEPRECATED_MSG(message) __attribute__((deprecated(message)))
#elif TLV_HAS_DECLSPEC_ATTRIBUTE(deprecated)
#define TLV_DEPRECATED_MSG(message) __declspec(deprecated(message))
#else
#define TLV_DEPRECATED_MSG(message)
#endif

/**
 * @brief Marks an intentional fall-through between adjacent `switch` cases.
 *
 * Used as a standalone statement, `TLV_FALLTHROUGH;`, as the last statement
 * of a `case` that intentionally falls into the next one. Expands to the
 * standard `[[fallthrough]]` attribute in C++17 or newer or in C23, to
 * `__attribute__((fallthrough))` on compilers that recognize it (GCC,
 * Clang), and to nothing otherwise, including the C99 baseline, where the
 * caller-supplied `;` alone forms a valid empty statement.
 */
#if TLV_ATTRIBUTES_HAS_STD_ATTR
#define TLV_FALLTHROUGH [[fallthrough]]
#elif TLV_HAS_ATTRIBUTE(fallthrough)
#define TLV_FALLTHROUGH __attribute__((fallthrough))
#else
#define TLV_FALLTHROUGH
#endif

#undef TLV_ATTRIBUTES_HAS_STD_ATTR

/** @} */

#endif /* OPENTLV_ATTRIBUTES_H */
