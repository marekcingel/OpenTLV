// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel
#ifndef OPENTLV_ASN1_QUERY_H
#define OPENTLV_ASN1_QUERY_H
#include "tlv/query/program.h"
#ifdef __cplusplus
extern "C" {
#endif
/** @file @ingroup traversal @brief ASN.1 Query semantic tag and date adapters. */
/** @brief Static class/number provider for valid BER/DER/CER identifiers.
 * Class values are 0 universal, 1 application, 2 context-specific, 3 private.
 * Number decomposition checks int64 narrowing; raw Tag identity never changes. */
extern TLV_API const tlv_query_tag_adapter_t tlv_asn1_query_tags;
/** @brief GeneralizedTime DATE provider (ID 4), UTC seconds with no fractional precision.
 * Uses the native GeneralizedTime Value codec and additionally validates Gregorian
 * calendar dates. Fractions are rejected, even zero fractions; no timezone guessing
 * or silent precision loss. Scratch is an aligned tlv_asn1_generalized_time_t.
 * The provider borrows no mutable storage and is safe for concurrent execution. */
extern TLV_API const tlv_query_hook_t tlv_asn1_query_date;
#ifdef __cplusplus
}
#endif
#endif
