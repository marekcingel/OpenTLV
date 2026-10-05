// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel
#ifndef OPENTLV_EMV_QUERY_H
#define OPENTLV_EMV_QUERY_H
#include "tlv/query/program.h"
#include "tlv/builtins/emv/emv.h"
#ifdef __cplusplus
extern "C" {
#endif
/**
 * @file
 * @ingroup traversal
 * @brief Native EMV Query name adapter.
 */
/** @brief Resolve canonical EMV Schema symbols in namespace emv; PAN aliases pan.
 * @param[in] context Borrowed tlv_emv_dictionary_t, or NULL for the base dictionary.
 * @param[in] namespace_name Optional bounded namespace, empty or emv.
 * @param[in] namespace_size Namespace bytes.
 * @param[in] name Bounded canonical symbol, case-sensitive except documented PAN alias.
 * @param[in] name_size Symbol bytes.
 * @param[out] tag Borrowed canonical identifier, copied by Query compilation.
 * @return OK, INVALID_TAG for unknown, INVALID_ARG for ambiguous symbols.
 * @note No codec selection or execution-time lookup occurs. */
TLV_API tlv_result_t tlv_emv_query_resolve(const void* context, const char* namespace_name,
                                           size_t namespace_size, const char* name,
                                           size_t name_size, tlv_tag_t* tag);
#ifdef __cplusplus
}
#endif
#endif
