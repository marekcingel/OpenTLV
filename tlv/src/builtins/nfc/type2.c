#include "tlv/builtins/nfc/type2.h"
#include "tlv/formats/escaped.h"

static const uint8_t codes[] = {TLV_NFC_TYPE2_NULL, TLV_NFC_TYPE2_TERMINATOR};
static const tlv_tag_t tag_only[] = {{&codes[0], 1}, {&codes[1], 1}};
static const tlv_escaped_format_t config = {1,
                                            {0xFF, 2, TLV_BYTE_ORDER_BIG_ENDIAN, 255, 65534},
                                            TLV_ELEMENT_ORDER_TLV,
                                            TLV_LENGTH_SCOPE_VALUE,
                                            tag_only,
                                            2};

const tlv_format_t tlv_format_nfc_type2 = {&config, tlv_escaped_decode, tlv_escaped_measure,
                                           tlv_escaped_encode, NULL};
