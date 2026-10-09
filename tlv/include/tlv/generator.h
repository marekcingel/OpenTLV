// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel
#ifndef OPENTLV_GENERATOR_H
#define OPENTLV_GENERATOR_H
#include "tlv/format.h"
#ifdef __cplusplus
extern "C" {
#endif
/** @file
 * @brief Deterministic allocation-free generation of Writer-reconstructible streams.
 */
/** @brief Wire generator algorithm version, changed when deterministic output changes. */
#define TLV_GENERATOR_VERSION 2
/** @brief A borrowed candidate identifier and permitted Value size interval.
 * Constructed identifiers are classified exclusively by Format and receive
 * generated child streams. Primitive Values contain arbitrary bytes; this is
 * wire generation, not Schema/Codec-valid content generation. Exclude stream
 * terminators and identifiers requiring contextual ordering from this table.
 */
typedef struct tlv_generator_candidate {
    tlv_tag_t tag;         /**< Borrowed identifier, including absent or explicitly empty Tags. */
    size_t min_value_size; /**< Inclusive minimum Value size in bytes. */
    size_t max_value_size; /**< Inclusive maximum Value size in bytes. */
} tlv_generator_candidate_t;
/** @brief Immutable configuration of one independently reproducible case.
 * Same algorithm version, immutable Format/configuration, ordered candidates,
 * options, seed and case index produce the same bytes, independent of earlier
 * calls and output capacity (provided capacity is sufficient).
 * Version 2 mixes the seed and case index in separate SplitMix64 finalization
 * stages. Different seed/index pairs are not a guarantee of unique wire bytes.
 */
typedef struct tlv_generator_options {
    uint64_t seed;         /**< Explicit seed; zero is valid. */
    uint64_t case_index;   /**< Random-access case index; zero is valid. */
    size_t max_elements;   /**< Positive total element bound, including parents. */
    size_t max_depth;      /**< Maximum child depth; roots have depth zero; at most 64. */
    size_t max_value_size; /**< Maximum Value size for every element in bytes. */
    size_t max_case_size;  /**< Positive maximum complete stream size in bytes. */
    const tlv_generator_candidate_t* candidates; /**< Borrowed ordered candidate table. */
    size_t candidate_count;                      /**< Positive table extent. */
} tlv_generator_options_t;
/** @brief Compute required caller-owned workspace without allocation.
 * @param[in] options Required validated configuration.
 * @param[out] size Required bytes: (max_depth + 1) * max_case_size.
 * @return #TLV_OK on success.
 * @return #TLV_ERR_NULL_ARG for missing arguments.
 * @return #TLV_ERR_INVALID_ARG for invalid limits or candidate intervals.
 * @return #TLV_ERR_OVERFLOW for unrepresentable workspace or attempt budget.
 * @note Output is unchanged on failure.
 */
TLV_API tlv_result_t tlv_generator_workspace_size(const tlv_generator_options_t* options,
                                                  size_t* size);
/** @brief Generate one nonempty complete stream through the canonical Writer.
 * A bounded search accepts only elements that decode completely and re-encode
 * byte-exactly. No independent wire encoder or protocol dispatch is used.
 * Candidate constraints must describe independently composable elements of
 * the selected Format. Message-level terminators, ordering and Schema policy
 * are not inferred from Format; configure an ordinary TLV stream domain.
 * Values deliberately sample interval ends and 127/128/255/256 boundaries.
 * @param[in] format Required readable and writable immutable Format.
 * @param[in] options Required immutable options and borrowed candidate storage.
 * @param[out] data Required output, at least max_case_size bytes.
 * @param[in] capacity Output capacity; extra capacity does not affect generation.
 * @param[in,out] workspace Required scratch storage, disjoint from output and inputs.
 * @param[in] workspace_size Available scratch bytes.
 * @param[out] written Required complete case size on success.
 * @return #TLV_OK on success.
 * @return #TLV_ERR_NULL_ARG for missing pointers or Format capabilities.
 * @return #TLV_ERR_INVALID_ARG for invalid configuration.
 * @return #TLV_ERR_OVERFLOW for unrepresentable workspace or attempt budget.
 * @return #TLV_ERR_BUFFER_TOO_SHORT for insufficient output or workspace.
 * @return #TLV_ERR_LIMIT if the bounded search cannot generate a nonempty case.
 * @note written is unchanged on failure; output and workspace bytes may change.
 * No storage is retained. Format callbacks must be deterministic and obey their contracts.
 */
TLV_API tlv_result_t tlv_generate(const tlv_format_t* format,
                                  const tlv_generator_options_t* options, uint8_t* data,
                                  size_t capacity, uint8_t* workspace, size_t workspace_size,
                                  size_t* written);
#ifdef __cplusplus
}
#endif
#endif
