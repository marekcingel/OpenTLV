// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel
#ifndef OPENTLV_QUERY_ADAPTERS_H
#define OPENTLV_QUERY_ADAPTERS_H
#include "tlv/query/program.h"
#ifdef __cplusplus
extern "C" {
#endif
/**
 * @file
 * @ingroup traversal
 * @brief Generic Definition and Value codec Query adapters.
 */
/** @brief One explicit namespace of borrowed descriptive definitions. */
typedef struct tlv_query_definition_scope {
    const char* namespace_name;                   /**< NUL-terminated namespace. */
    const tlv_definition_registry_t* definitions; /**< Borrowed immutable registry. */
} tlv_query_definition_scope_t;
/** @brief Compile-time scope collection, not a protocol dictionary. */
typedef struct tlv_query_definition_resolver {
    const tlv_query_definition_scope_t* scopes; /**< Borrowed namespace entries. */
    size_t count;                               /**< Entry count. */
} tlv_query_definition_resolver_t;
/** @brief Resolve names using exact registry labels in explicit namespaces.
 * @param[in] context Required tlv_query_definition_resolver_t.
 * @param[in] namespace_name Bounded optional namespace.
 * @param[in] namespace_size Namespace bytes; zero searches all scopes.
 * @param[in] name Bounded descriptive name.
 * @param[in] name_size Name bytes.
 * @param[out] tag Borrowed tag, unchanged on failure.
 * @return OK, INVALID_TAG for unknown, INVALID_ARG for multiple matches,
 * or NULL_ARG for invalid pointer arguments. No allocation or codec policy. */
TLV_API tlv_result_t tlv_query_definition_resolve(const void* context, const char* namespace_name,
                                                  size_t namespace_size, const char* name,
                                                  size_t name_size, tlv_tag_t* tag);
/** @brief Explicit decoded C representation for adapting an existing Value codec. */
typedef enum tlv_query_codec_representation {
    TLV_QUERY_CODEC_SIGNED,   /**< int64_t result. */
    TLV_QUERY_CODEC_UNSIGNED, /**< uint64_t, checked before int64 narrowing. */
    TLV_QUERY_CODEC_UTF8      /**< tlv_value_t span, validated UTF-8 without allocation. */
} tlv_query_codec_representation_t;
/** @brief Borrowed domain composition; codec selection never belongs to Definition. */
typedef struct tlv_query_codec_adapter {
    const tlv_codec_t* codec;                        /**< Borrowed codec and its context. */
    tlv_query_codec_representation_t representation; /**< Explicit decoded object type. */
} tlv_query_codec_adapter_t;
/** @brief Decode a complete Value with an existing codec, preserving codec errors.
 * @param[in] context Required tlv_query_codec_adapter_t.
 * @param[in] event Optional metadata, unused by this generic adapter.
 * @param[in] data Complete Value bytes.
 * @param[in] size Value bytes.
 * @param[in,out] scratch Aligned representation storage.
 * @param[in] capacity Representation bytes.
 * @param[out] result Integer or UTF-8 string output.
 * @return Original codec status; unsigned overflow maps to INVALID_VALUE.
 * @note No allocation. UTF-8 validation adds linear external adapter work. * @param[out] diagnostic
 * Optional initialized failure output; NULL skips evidence collection.
 */
TLV_API tlv_result_t tlv_query_codec_decode(const void* context, const tlv_tree_event_t* event,
                                            const uint8_t* data, size_t size, void* scratch,
                                            size_t capacity, tlv_query_result_t* result,
                                            tlv_codec_diagnostic_t* diagnostic);
/** @brief Static native generic NUM/BCD/TEXT providers, IDs 1/2/3.
 * NUM uses minimal signed big-endian int64; BCD uses unsigned packed decimal
 * with at most 18 digits; TEXT uses borrowed UTF-8 bytes. Domain codecs may
 * replace these by explicit adapters and distinct stable capability IDs.
 * @param[out] count Optional provider count.
 * @return Borrowed immutable provider array. */
TLV_API const tlv_query_hook_t* tlv_query_builtin_hooks(size_t* count);
#ifdef __cplusplus
}
#endif
#endif
