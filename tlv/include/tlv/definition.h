// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#ifndef OPENTLV_DEFINITION_H
#define OPENTLV_DEFINITION_H

#include "tlv/tag.h"
#include "tlv/export.h"

/**
 * @file
 * @ingroup core
 * @brief Format-independent identifier definitions and lookup.
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief An identifier and its descriptive name.
 *
 * Both fields borrow immutable storage. No allocation, encoding rules,
 * value interpretation or schema constraints are implied.
 * Identifier meaning is scoped to the selected registry, not global across
 * standards. The name is descriptive, not a unique symbol or domain identity.
 * Canonical identifier bytes need not equal the raw wire header bytes.
 * Rich domain dictionaries may compose these entries with schema, codec and
 * protocol metadata; such metadata does not belong in this generic contract.
 */
typedef struct {
    /** Canonical identifier bytes; storage must outlive the definition's use. */
    tlv_tag_t tag;
    /** Borrowed NUL-terminated name, or `NULL` when unnamed. */
    const char* name;
} tlv_definition_t;

/**
 * @brief A borrowed table of identifier definitions.
 *
 * No allocation or registration occurs. Keep the entries, tag bytes and names
 * alive and unchanged while using the registry or a returned entry pointer.
 * Callers select the registry for their domain/context. Lookup does not resolve
 * context, select a codec or map identifiers between formats.
 */
typedef struct {
    /** Borrowed entries; may be `NULL` only when count is zero. */
    const tlv_definition_t* entries;
    /** Number of entries, not bytes. */
    size_t count;
} tlv_definition_registry_t;

/**
 * @brief Finds the first definition with the same tag size and bytes.
 *
 * Uses tlv_tag_equal(), including its empty-tag equality. Invalid entry tags
 * are skipped. No sorting is required and no allocation occurs. A missing
 * definition does not make an identifier structurally invalid.
 *
 * @param[in] registry Registry to search; may be `NULL`.
 * @param[in] tag Identifier to find; may be `NULL`.
 * @return A borrowed pointer to the first matching entry.
 * @return `NULL` for an unknown tag, NULL arguments, an invalid lookup tag,
 *         or a missing nonempty table.
 */
TLV_API const tlv_definition_t* tlv_definition_find(const tlv_definition_registry_t* registry,
                                                    const tlv_tag_t* tag);

#ifdef __cplusplus
}
#endif

#endif /* OPENTLV_DEFINITION_H */
