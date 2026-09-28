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
