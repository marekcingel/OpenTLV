// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#ifndef OPENTLV_FIELD_VARIABLE_H
#define OPENTLV_FIELD_VARIABLE_H

#include "tlv/tag.h"
#include "tlv/size.h"
#include "tlv/endian.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file
 * @ingroup field_encoding
 * @brief Configurable variable-width identifier and count primitives.
 *
 * Configurations are immutable and borrowed. No operation allocates. Identifiers
 * retain their complete wire byte identity, including prefix bits; no numeric
 * tag interpretation is imposed. Optional declarative policies constrain wire
 * encodings; protocol semantics remain in concrete formats. These primitives
 * do not depend on any builtin.
 */

/** @addtogroup field_encoding
 * @{
 */

/**
 * @brief Optional constraints on a variable identifier's wire representation.
 *
 * Forbidden leading bytes and a zero first escaped payload are checked before
 * parsing the rest of the identifier, including on truncated input. Minimality
 * rejects redundant leading zero digits and escaped numbers that could be inline
 * (the escape number itself cannot be inline). Payload bits are packed low to
 * high; arbitrarily wide identifiers are checked without narrowing to uint64_t.
 * Tables and policy are borrowed and must remain immutable for all operations.
 */
typedef struct tlv_identifier_policy {
    const uint8_t* forbidden_leading;   /**< Forbidden first bytes; NULL only with zero count. */
    size_t forbidden_leading_count;     /**< Number of bytes in the borrowed table. */
    unsigned reject_zero_first_payload; /**< Boolean: reject zero first escaped payload. */
    unsigned require_minimal; /**< Boolean: require shortest identifier number representation. */
} tlv_identifier_policy_t;

/**
 * @brief Allowed definite count forms and numeric limits.
 *
 * At least one form must be allowed. Minimality uses the shortest allowed form:
 * with short form disabled, zero uses one long-form octet. Decoding checks form
 * and width limits before requiring the payload, then checks value/minimality.
 * Counts outside max_value, including arithmetic overflow, are INVALID_LENGTH.
 * Indefinite counts and terminated-value resolution are not part of this policy.
 */
typedef struct tlv_length_policy {
    unsigned allow_short;     /**< Boolean: permit inline counts. */
    unsigned allow_long;      /**< Boolean: permit nonzero long-form counts. */
    unsigned require_minimal; /**< Boolean: reject padding and unnecessary long form. */
    size_t max_long_octets;   /**< Maximum following octets; positive when allow_long is set. */
    tlv_size_t max_value;     /**< Inclusive count limit; zero permits only zero. */
} tlv_length_policy_t;

/**
 * @brief Inline identifier bits with an escape into continuation octets.
 *
 * One octet is sufficient unless `(first & inline_mask) == escape`. In that
 * case at least one continuation octet follows, ending when continuation_bit
 * is clear. Only payload_mask and continuation_bit may be set in those octets.
 * Without a policy, zero payloads and nonminimal forms are accepted. Bits outside inline_mask
 * in the first octet are preserved without interpretation.
 */
typedef struct tlv_variable_identifier {
    uint8_t inline_mask;      /**< Nonzero mask selecting inline bits in the first octet. */
    uint8_t escape;           /**< Escape pattern, containing only inline_mask bits. */
    uint8_t continuation_bit; /**< Exactly one bit; set means another octet follows. */
    uint8_t payload_mask;     /**< Nonzero payload mask, disjoint from continuation_bit. */
    size_t max_size;          /**< Maximum complete identifier width in bytes; at least one. */
    const tlv_identifier_policy_t* policy; /**< Optional borrowed immutable wire constraints. */
} tlv_variable_identifier_t;

/**
 * @brief Short unsigned count or a prefix specifying the following octet count.
 *
 * When long_form_bit is clear, payload_mask holds the count itself. Otherwise
 * it holds the number of following full octets, interpreted in byte_order.
 * Mask bits are packed from least to most significant, even for noncontiguous
 * masks. Other prefix bits must be zero. A long-form octet count of zero has
 * no definite count and is rejected by this primitive; a concrete format may
 * recognize it in its bounds resolver. No prefix is reserved by a standard.
 * Without a policy, reading accepts padded and nonminimal counts that fit
 * #tlv_size_t. Writing uses the shortest allowed form and full count width.
 */
typedef struct tlv_variable_length {
    uint8_t long_form_bit;             /**< Exactly one bit selecting long form. */
    uint8_t payload_mask;              /**< Nonzero mask, disjoint from long_form_bit. */
    tlv_byte_order_t byte_order;       /**< Order of the full count octets in long form. */
    const tlv_length_policy_t* policy; /**< Optional borrowed immutable definite count policy. */
} tlv_variable_length_t;

/**
 * @brief Read a complete variable identifier without copying its bytes.
 *
 * @param[in] config Immutable identifier configuration, not NULL.
 * @param[in] data Source bytes; NULL is allowed only when size is zero.
 * @param[in] size Available source bytes.
 * @param[out] tag Identifier borrowing data, which must outlive the result.
 * @param[out] consumed Complete width on success; available prefix on incomplete input.
 * @return #TLV_OK on success.
 * @return #TLV_ERR_NULL_ARG for a missing required pointer.
 * @return #TLV_ERR_INVALID_ARG for invalid configuration.
 * @return #TLV_ERR_TRUNCATED for a missing prefix or continuation octet.
 * @return #TLV_ERR_INVALID_TAG_SIZE if the identifier would exceed max_size.
 * @return #TLV_ERR_INVALID_TAG for invalid bits or a policy violation.
 * @note Validate required pointers, configuration, then available wire bytes.
 * Incomplete input sets *consumed to size; other failures preserve consumed.
 * The tag is unchanged on failure. No allocation occurs.
 */
TLV_API tlv_result_t tlv_variable_identifier_read(const tlv_variable_identifier_t* config,
                                                  const uint8_t* data, size_t size, tlv_tag_t* tag,
                                                  size_t* consumed);

/**
 * @brief Validate and copy a raw identifier, or measure it with NULL output.
 *
 * @param[in] config Immutable identifier configuration, not NULL.
 * @param[in] tag Complete raw identifier, not NULL.
 * @param[out] data Destination; NULL with zero capacity queries the width.
 * @param[in] capacity Destination capacity in bytes.
 * @param[out] written Complete identifier width on success.
 * @return #TLV_OK on success.
 * @return #TLV_ERR_NULL_ARG for missing pointers or NULL data with nonzero capacity.
 * @return #TLV_ERR_INVALID_ARG for invalid configuration.
 * @return #TLV_ERR_INVALID_TAG_SIZE for an empty or oversized identifier.
 * @return #TLV_ERR_INVALID_TAG for an incomplete identifier, trailing bytes or invalid bits.
 * @return #TLV_ERR_BUFFER_TOO_SHORT for insufficient destination capacity.
 * @note Validate required pointers, configuration, identifier constraints and
 * capacity in that order. Outputs are unchanged on failure. Source and destination
 * may overlap.
 */
TLV_API tlv_result_t tlv_variable_identifier_write(const tlv_variable_identifier_t* config,
                                                   const tlv_tag_t* tag, uint8_t* data,
                                                   size_t capacity, size_t* written);

/**
 * @brief Decode a definite count without narrowing to native size.
 *
 * @param[in] config Immutable count configuration, not NULL.
 * @param[in] data Source bytes; NULL is allowed only when size is zero.
 * @param[in] size Available source bytes.
 * @param[out] length Decoded count on success; unchanged on failure.
 * @param[out] consumed Field width on success; available field prefix on wire errors.
 * @return #TLV_OK on success.
 * @return #TLV_ERR_NULL_ARG for a missing required pointer.
 * @return #TLV_ERR_INVALID_ARG for invalid masks or policy configuration.
 * @return #TLV_ERR_INVALID_ARG for an unknown byte order.
 * @return #TLV_ERR_TRUNCATED for an incomplete field.
 * @return #TLV_ERR_INVALID_LENGTH for invalid prefix, zero long-form width or policy violation.
 * @return #TLV_ERR_OVERFLOW if an unconstrained count exceeds #tlv_size_t.
 * @note Validate required pointers and configuration before inspecting wire bytes.
 * Argument/configuration errors leave both outputs unchanged. Incomplete input
 * reports the available prefix through consumed.
 */
TLV_API tlv_result_t tlv_variable_length_read(const tlv_variable_length_t* config,
                                              const uint8_t* data, size_t size, tlv_size_t* length,
                                              size_t* consumed);

/**
 * @brief Encode a definite count, or measure it with NULL output.
 *
 * @param[in] config Immutable count configuration, not NULL.
 * @param[in] length Logical unsigned count.
 * @param[out] data Destination; NULL with zero capacity queries the width.
 * @param[in] capacity Destination capacity in bytes.
 * @param[out] written Encoded count field width on success.
 * @return #TLV_OK on success.
 * @return #TLV_ERR_NULL_ARG for missing pointers or NULL data with nonzero capacity.
 * @return #TLV_ERR_INVALID_ARG for invalid masks or policy configuration.
 * @return #TLV_ERR_INVALID_ARG for an unknown byte order.
 * @return #TLV_ERR_INVALID_LENGTH for an unrepresentable width or policy violation.
 * @return #TLV_ERR_BUFFER_TOO_SHORT for insufficient destination capacity.
 * @note Validate required pointers, configuration, count representability and
 * capacity in that order. Outputs are unchanged on failure. No allocation occurs.
 */
TLV_API tlv_result_t tlv_variable_length_write(const tlv_variable_length_t* config,
                                               tlv_size_t length, uint8_t* data, size_t capacity,
                                               size_t* written);

/** @} */

#ifdef __cplusplus
}
#endif
#endif
