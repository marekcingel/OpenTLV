#ifndef OPENTLV_DIAGNOSTIC_H
#define OPENTLV_DIAGNOSTIC_H

#include "tlv/error.h"
#include "tlv/export.h"
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
