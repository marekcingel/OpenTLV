#ifndef OPENTLV_SCHEMA_CONSTRAINT_H
#define OPENTLV_SCHEMA_CONSTRAINT_H
#include "tlv/error.h"
#include "tlv/export.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file
 * @ingroup schemas
 * @brief Generic value constraints checked against a decoded value.
 */

/** @addtogroup schemas
 * @{
 */

/** @brief Kind of constraint a #tlv_value_constraint_t applies to a decoded value. */
typedef enum tlv_value_constraint_kind {
    /** No constraint; every value is permitted (the default). */
    TLV_VALUE_CONSTRAINT_NONE = 0,
    /** Value must be within [min_value, max_value], inclusive. */
    TLV_VALUE_CONSTRAINT_RANGE,
    /** Value must equal one entry of allowed_values. */
    TLV_VALUE_CONSTRAINT_ALLOWED_VALUES
} tlv_value_constraint_kind_t;

/**
 * @brief Generic constraint on one decoded scalar value, such as an ASN.1
 * INTEGER (X.690) value range or a fixed set of legal values.
 *
 * Checked against the C representation a #tlv_codec_t decode produces (for
 * example tlv_asn1_codec_integer's `int64_t`), not against raw TLV bytes;
 * pair it with a codec's decode step. Byte-length and occurrence bounds are
 * unrelated concerns already covered by #tlv_schema_entry_t's `min_length`/
 * `max_length` and #tlv_structure_rule_t's `min_occurs`/`max_occurs`.
 */
typedef struct tlv_value_constraint {
    /** Which fields below apply. */
    tlv_value_constraint_kind_t kind;
    /** Minimum permitted value, inclusive; used only for #TLV_VALUE_CONSTRAINT_RANGE. */
    int64_t min_value;
    /** Maximum permitted value, inclusive; used only for #TLV_VALUE_CONSTRAINT_RANGE. */
    int64_t max_value;
    /** Borrowed permitted values; used only for #TLV_VALUE_CONSTRAINT_ALLOWED_VALUES; may be
     * `NULL` only when `allowed_values_count` is 0. */
    const int64_t* allowed_values;
    /** Number of entries in `allowed_values`. */
    size_t allowed_values_count;
} tlv_value_constraint_t;

/**
 * @brief Validates a decoded scalar value against a constraint.
 *
 * Checks only the value, independently of decoding; combine with
 * tlv_codec_decode() (or an equivalent) to validate an ASN.1-style value
 * range or allowed-value set on a raw TLV element's content.
 *
 * @param[in] constraint Constraint to check against.
 * @param[in] value      Decoded value to check.
 *
 * @return #TLV_OK if `constraint->kind` is #TLV_VALUE_CONSTRAINT_NONE, or `value` satisfies
 *         the constraint.
 * @return #TLV_ERR_SCHEMA if `value` violates the constraint, `kind` is unrecognized,
 *         #TLV_VALUE_CONSTRAINT_RANGE has `min_value > max_value`, or
 *         #TLV_VALUE_CONSTRAINT_ALLOWED_VALUES has a `NULL` `allowed_values` with a nonzero
 *         `allowed_values_count`.
 * @return #TLV_ERR_NULL_ARG if `constraint` is `NULL`.
 */
TLV_API tlv_result_t tlv_value_constraint_validate(const tlv_value_constraint_t* constraint,
                                                   int64_t value);

#ifdef __cplusplus
}
#endif

/** @} */

#endif /* OPENTLV_SCHEMA_CONSTRAINT_H */
