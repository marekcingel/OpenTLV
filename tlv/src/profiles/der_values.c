#include "der_values_internal.h"
#include "asn1_values_internal.h"

/* Dispatches to the ASN.1 canonical content validators shared with CER (see
 * asn1_values_internal.h), following ITU-T X.690 (10/2021 edition), section 11. */
tlv_result_t tlv_der_validate_universal_value(uint64_t number, const uint8_t* value, size_t length) {
    return tlv_asn1_validate_universal_value(number, value, length);
}
