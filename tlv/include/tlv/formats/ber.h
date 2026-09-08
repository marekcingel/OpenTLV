#ifndef OPENTLV_FORMATS_BER_H
#define OPENTLV_FORMATS_BER_H

#include "tlv/formats/format.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Raw BER-TLV tags up to TLV_TAG_MAX_SIZE, including high-tag-number form.
 * Definite lengths up to SIZE_MAX; writes use the shortest length encoding.
 * Reads accept nonminimal definite lengths. Indefinite lengths are rejected.
 * Tag bytes are preserved (including 9F 1C); ASN.1 semantics are not validated.
 */
extern const tlv_format_t tlv_format_ber;

#ifdef __cplusplus
}
#endif
#endif
