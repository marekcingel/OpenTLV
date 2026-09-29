#ifndef OPENTLV_BUILTINS_EMV_SCHEMA_H
#define OPENTLV_BUILTINS_EMV_SCHEMA_H

#include "tlv/schema/schema.h"
#include "tlv/export.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file
 * @ingroup schemas
 * @brief Structural schema for common EMV Book 3 v4.4 top-level data objects.
 */

/** @addtogroup schemas
 * @{
 */

/**
 * @brief Structural validation schema for common EMV Book 3 v4.4 top-level data objects.
 *
 * Complements the per-tag length rules in #tlv_emv_schema
 * (tlv/builtins/emv/emv.h) with the mandatory, forbidden, duplicate and nesting
 * checks that schema explicitly leaves to the application (see "Validation
 * limits" in docs/standards/emv/README.md).
 *
 * Modeled: the FCI Template (6F, Book 3 section 11.3.4 Table 12) and its FCI
 * Proprietary Template (A5) child, the Application Template (61, Book 1
 * Table 8), and the GPO Response Message Template Format 2 (77, Book 3
 * Table 3). Unmodeled top-level tags (Read Record Template 70, Response
 * Message Template Format 1 80, issuer script templates, proprietary data,
 * etc.) are accepted unchecked at the root, because their contents vary too
 * much by kernel and issuer for a generic schema.
 *
 * Use with tlv_schema_validate() and #tlv_format_emv, whose `is_constructed`
 * reports the wire constructed bit. Semantic primitive-bit templates are
 * outside this structural schema and require explicit application traversal.
 */
extern TLV_API const tlv_structure_schema_t tlv_emv_structure_schema;

#ifdef __cplusplus
}
#endif
/** @} */

#endif /* OPENTLV_BUILTINS_EMV_SCHEMA_H */
