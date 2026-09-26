#ifndef OPENTLV_COMPILER_H
#define OPENTLV_COMPILER_H

/**
 * @file
 * @ingroup core
 * @brief Centralized C language version and compiler capability detection.
 *
 * OpenTLV's public headers and ABI target C99. This header lets other public
 * headers, such as tlv/attributes.h, query the active language version and
 * compiler capabilities from one place instead of repeating
 * `__STDC_VERSION__` or compiler-specific checks; feature detection is
 * preferred over compiler-name detection wherever a feature-detection macro
 * exists. It defines no functions or types, only preprocessor macros, so it
 * needs no `extern "C"` guard and is safe to include from both C and C++
 * translation units.
 */

/** @addtogroup core
 * @{
 */

/** @brief `__STDC_VERSION__` value identifying C99. */
#define TLV_C99 199901L
/** @brief `__STDC_VERSION__` value identifying C11. */
#define TLV_C11 201112L
/** @brief `__STDC_VERSION__` value identifying C17. */
#define TLV_C17 201710L
/** @brief `__STDC_VERSION__` value identifying C23. */
#define TLV_C23 202311L

/**
 * @brief The active C standard version, comparable against #TLV_C99, #TLV_C11,
 * #TLV_C17 and #TLV_C23.
 *
 * Expands to `__STDC_VERSION__` when compiling as C. C++ has no equivalent
 * macro, so a C++ translation unit sees #TLV_C99 here; C++-specific checks
 * should test `__cplusplus` directly instead of this macro.
 */
#if defined(__STDC_VERSION__)
#define TLV_C_VERSION __STDC_VERSION__
#else
#define TLV_C_VERSION TLV_C99
#endif

/** @brief Nonzero when #TLV_C_VERSION is C11 or newer. */
#define TLV_HAS_C11 (TLV_C_VERSION >= TLV_C11)
/** @brief Nonzero when #TLV_C_VERSION is C17 or newer. */
#define TLV_HAS_C17 (TLV_C_VERSION >= TLV_C17)
/** @brief Nonzero when #TLV_C_VERSION is C23 or newer. */
#define TLV_HAS_C23 (TLV_C_VERSION >= TLV_C23)

/**
 * @brief Nonzero when the active compiler recognizes attribute `x` via the
 * `__has_attribute` compiler builtin.
 *
 * Expands to `__has_attribute(x)` where supported (Clang and modern GCC) and
 * to `0` otherwise, so it can be used unconditionally in an `#if` without
 * first checking whether `__has_attribute` itself exists.
 */
#ifdef __has_attribute
#define TLV_HAS_ATTRIBUTE(x) __has_attribute(x)
#else
#define TLV_HAS_ATTRIBUTE(x) 0
#endif

/**
 * @brief Nonzero when the active compiler recognizes builtin `x` via the
 * `__has_builtin` compiler builtin.
 *
 * Expands to `__has_builtin(x)` where supported (Clang and modern GCC) and to
 * `0` otherwise, so it can be used unconditionally in an `#if` without first
 * checking whether `__has_builtin` itself exists.
 */
#ifdef __has_builtin
#define TLV_HAS_BUILTIN(x) __has_builtin(x)
#else
#define TLV_HAS_BUILTIN(x) 0
#endif

/**
 * @brief Nonzero when the active compiler recognizes `__declspec` attribute
 * `x` via the `__has_declspec_attribute` compiler builtin.
 *
 * Expands to `__has_declspec_attribute(x)` where supported (MSVC and
 * clang-cl) and to `0` otherwise, so it can be used unconditionally in an
 * `#if` without first checking whether `__has_declspec_attribute` itself
 * exists.
 */
#ifdef __has_declspec_attribute
#define TLV_HAS_DECLSPEC_ATTRIBUTE(x) __has_declspec_attribute(x)
#else
#define TLV_HAS_DECLSPEC_ATTRIBUTE(x) 0
#endif

/** @} */

#endif /* OPENTLV_COMPILER_H */
