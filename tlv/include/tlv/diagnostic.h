#ifndef OPENTLV_DIAGNOSTIC_H
#define OPENTLV_DIAGNOSTIC_H

#include "tlv/error.h"
#include "tlv/export.h"
#include "tlv/tag.h"
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file
 * @ingroup diagnostics
 * @brief Structured diagnostic model shared across OpenTLV layers.
 */

/** @addtogroup diagnostics
 * @{
 */

/** @brief How serious a #tlv_diagnostic_t is. */
typedef enum tlv_diagnostic_severity {
    /** The operation that produced the diagnostic cannot proceed. */
    TLV_DIAGNOSTIC_SEVERITY_ERROR = 0,
    /** The operation can proceed, but the result may not be what was intended. */
    TLV_DIAGNOSTIC_SEVERITY_WARNING,
    /** Informational detail that does not affect the outcome. */
    TLV_DIAGNOSTIC_SEVERITY_INFO
} tlv_diagnostic_severity_t;

/**
 * @brief One piece of context a layer has attached to a #tlv_diagnostic_t.
 *
 * A context node is caller-provided storage linked onto a diagnostic's
 * `contexts` chain by tlv_diagnostic_add_context(); nothing is copied or
 * allocated. `layer`, `key` and `value` are borrowed and must stay valid, and
 * `context` itself must stay valid and unmoved, for as long as the diagnostic
 * is used.
 */
typedef struct tlv_diagnostic_context {
    /** Name of the layer that added this context, for example `"ber"` or `"schema"`. */
    const char* layer;
    /** Name of the attribute, for example `"declared_length"`. */
    const char* key;
    /** Formatted value of the attribute, for example `"6"`. */
    const char* value;
    /** Next, outer context in the chain, or `NULL` for the last one. */
    const struct tlv_diagnostic_context* next;
} tlv_diagnostic_context_t;

/** @brief Maximum number of tags a #tlv_diagnostic_path_t can hold. */
enum { TLV_DIAGNOSTIC_PATH_MAX = 32 };

/**
 * @brief Bounded, allocation-free stack of the tags enclosing a #tlv_diagnostic_t.
 *
 * A caller that traverses nested constructed TLVs, for example with
 * tlv_walk_tree() or by recursing into a value's bytes, builds a path by
 * calling tlv_diagnostic_path_push() with the tag of each element it
 * descends into and tlv_diagnostic_path_pop() when it returns to the
 * parent. `tags` then lists the enclosing elements outermost first, so it
 * identifies the exact branch of a document that led to a diagnostic even
 * when the same tag repeats at different depths. Nothing is copied or
 * allocated: pushing a tag stores its borrowed `data`/`size` pair, which
 * must stay valid, and unchanged, for as long as the path is used.
 *
 * Path tracking is entirely opt-in: a #tlv_diagnostic_t that is never given
 * a path costs nothing beyond the one `NULL` pointer in `path`.
 */
typedef struct tlv_diagnostic_path {
    /** Enclosing tags, outermost first; `length` entries are valid. */
    tlv_tag_t tags[TLV_DIAGNOSTIC_PATH_MAX];
    /** Number of valid entries in `tags`. */
    size_t length;
} tlv_diagnostic_path_t;

/**
 * @brief Initializes a path as empty.
 *
 * @param[out] path Path to initialize; must not be `NULL`.
 */
TLV_API void tlv_diagnostic_path_init(tlv_diagnostic_path_t* path);

/**
 * @brief Pushes a tag onto the end of a path.
 *
 * Call this when descending into the constructed element identified by
 * `tag`, before visiting its children.
 *
 * @param[in,out] path Path to update; must not be `NULL`.
 * @param[in]     tag  Tag of the element being descended into; borrowed, and must stay
 *                     valid for as long as the path is used.
 *
 * @return #TLV_OK on success.
 * @return #TLV_ERR_NULL_ARG if `path` is `NULL`.
 * @return #TLV_ERR_LIMIT if the path already holds #TLV_DIAGNOSTIC_PATH_MAX
 *         tags; `path` is unchanged.
 */
TLV_API tlv_result_t tlv_diagnostic_path_push(tlv_diagnostic_path_t* path, tlv_tag_t tag);

/**
 * @brief Pops the last tag off a path.
 *
 * Call this when returning from the constructed element last pushed, after
 * visiting its children. Popping an empty path is a no-op.
 *
 * @param[in,out] path Path to update; must not be `NULL`.
 */
TLV_API void tlv_diagnostic_path_pop(tlv_diagnostic_path_t* path);

/**
 * @brief Formats a path as uppercase hexadecimal tags joined by `" > "`.
 *
 * For example `"6F > A5 > BF0C > 61 > 4F"`. An empty path formats as an
 * empty string. The text is NUL-terminated when it fits.
 *
 * @param[in]  path     Path to format.
 * @param[out] out      Destination; may be `NULL` only if `capacity` is zero.
 * @param[in]  capacity Size of `out` in bytes, including the terminator.
 * @param[out] length   Receives the text length without the terminator, also
 *                      when `out` is too small. May be `NULL`.
 *
 * @return #TLV_OK on success.
 * @return #TLV_ERR_NULL_ARG if `path` or a required `out` is `NULL`.
 * @return #TLV_ERR_INVALID_ARG if `path->length` exceeds #TLV_DIAGNOSTIC_PATH_MAX
 *         or a tag in `path` is invalid.
 * @return #TLV_ERR_BUFFER_TOO_SHORT if `capacity` is below `*length + 1`.
 */
TLV_API tlv_result_t tlv_diagnostic_path_string(const tlv_diagnostic_path_t* path, char* out,
                                                size_t capacity, size_t* length);

/**
 * @brief A structured diagnostic: a stable code plus the state that produced it.
 *
 * The core representation is independent of any wire format, schema or
 * higher-level protocol. A format, schema, profile or application layer
 * enriches a diagnostic that a lower layer produced by chaining
 * #tlv_diagnostic_context_t entries onto `contexts` with
 * tlv_diagnostic_add_context(), instead of defining its own diagnostic type.
 * Rendering a diagnostic for humans is a separate concern, not part of this
 * type.
 *
 * Every field is a fixed-size value or a borrowed pointer; a diagnostic never
 * allocates and never owns the memory it points to.
 */
typedef struct tlv_diagnostic {
    /** Stable code identifying the failure or observation. */
    tlv_result_t code;
    /** How serious the diagnostic is. */
    tlv_diagnostic_severity_t severity;
    /** Nonzero if `offset` is set. */
    int has_offset;
    /** Input or output byte offset the diagnostic refers to; valid only if `has_offset` is nonzero.
     */
    size_t offset;
    /** Borrowed description of what was expected, or `NULL` if not applicable. */
    const char* expected;
    /** Borrowed description of what was actually found, or `NULL` if not applicable. */
    const char* actual;
    /** Innermost context first, outermost last; `NULL` if nothing has been attached. */
    const tlv_diagnostic_context_t* contexts;
    /** Enclosing tags leading to this diagnostic, or `NULL` if not tracked. */
    const tlv_diagnostic_path_t* path;
} tlv_diagnostic_t;

/**
 * @brief Initializes a diagnostic with a code and severity, and no location, expectation or
 * context.
 *
 * @param[out] diagnostic Diagnostic to initialize; must not be `NULL`.
 * @param[in]  code       Stable code identifying the failure or observation.
 * @param[in]  severity   How serious the diagnostic is.
 */
TLV_API void tlv_diagnostic_init(tlv_diagnostic_t* diagnostic, tlv_result_t code,
                                 tlv_diagnostic_severity_t severity);

/**
 * @brief Sets the byte offset a diagnostic refers to.
 *
 * @param[in,out] diagnostic Diagnostic to update; must not be `NULL`.
 * @param[in]     offset     Input or output byte offset.
 *
 * @note Also sets `has_offset` to nonzero.
 */
TLV_API void tlv_diagnostic_set_offset(tlv_diagnostic_t* diagnostic, size_t offset);

/**
 * @brief Attaches one context entry to a diagnostic.
 *
 * Links `context` onto the front of `diagnostic->contexts`, so the most
 * recently added context is innermost. Nothing is copied or allocated.
 *
 * @param[in,out] diagnostic Diagnostic to update; must not be `NULL`.
 * @param[out]    context    Caller-owned storage for the new entry; must not be `NULL`. Every field
 *                           is overwritten.
 * @param[in]     layer      Borrowed name of the layer adding context, for example `"ber"`.
 * @param[in]     key        Borrowed name of the attribute, for example `"declared_length"`.
 * @param[in]     value      Borrowed formatted value of the attribute.
 *
 * @warning `context` and the strings passed in must stay valid, and `context` must stay at the same
 *          address, for as long as the diagnostic is used.
 */
TLV_API void tlv_diagnostic_add_context(tlv_diagnostic_t* diagnostic,
                                        tlv_diagnostic_context_t* context, const char* layer,
                                        const char* key, const char* value);

/**
 * @brief Sets the hierarchical path a diagnostic refers to.
 *
 * @param[in,out] diagnostic Diagnostic to update; must not be `NULL`.
 * @param[in]     path       Borrowed path of enclosing tags, or `NULL` to clear it.
 *
 * @warning `path` and the tags it holds must stay valid, and unchanged, for
 *          as long as the diagnostic is used.
 */
TLV_API void tlv_diagnostic_set_path(tlv_diagnostic_t* diagnostic,
                                     const tlv_diagnostic_path_t* path);

/**
 * @brief Returns a short name for a severity.
 *
 * @param[in] severity Severity to describe.
 *
 * @return A static, NUL-terminated string such as `"error"`, never `NULL`; an
 *         unrecognized value yields `"unknown"`.
 */
TLV_API const char* tlv_diagnostic_severity_string(tlv_diagnostic_severity_t severity);

#ifdef __cplusplus
}
#endif

/** @} */

#endif /* OPENTLV_DIAGNOSTIC_H */
