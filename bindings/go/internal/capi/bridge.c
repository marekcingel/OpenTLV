// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel
#include "bridge.h"
#if OPENTLV_FORMAT_BER
#include <tlv/builtins/asn1/ber.h>
#endif
#if OPENTLV_FORMAT_DER
#include <tlv/builtins/asn1/der.h>
#endif
#if OPENTLV_FORMAT_CER
#include <tlv/builtins/asn1/cer.h>
#endif
#if OPENTLV_EMV
#include <tlv/builtins/emv/format.h>
#endif
#if OPENTLV_LLDP
#include <tlv/builtins/lldp/lldp.h>
#endif
#if OPENTLV_BLUETOOTH
#include <tlv/builtins/bluetooth/bluetooth_ltv.h>
#endif
#if OPENTLV_DHCP
#include <tlv/builtins/dhcp/dhcpv4.h>
#endif
#if OPENTLV_NFC
#include <tlv/builtins/nfc/type2.h>
#endif

/* All descriptors, contexts and cursors are call-local. No Go pointer is retained. */
static tlv_result_t resolve(go_format config, tlv_format_t* format, tlv_fixed_format_t* fixed) {
    switch (config.kind) {
        case GO_FORMAT_FIXED:
            fixed->tag_size = config.tag_size;
            fixed->length_size = config.length_size;
            fixed->length_order = (tlv_byte_order_t)config.byte_order;
            fixed->element_order = (tlv_element_order_t)config.element_order;
            fixed->length_scope = (tlv_length_scope_t)config.length_scope;
            return tlv_fixed_format_init(format, fixed);
#if OPENTLV_FORMAT_BER
        case GO_FORMAT_BER: *format = tlv_format_ber; return TLV_OK;
        case GO_FORMAT_BER_INDEFINITE: *format = tlv_format_ber_indefinite; return TLV_OK;
#endif
#if OPENTLV_FORMAT_DER
        case GO_FORMAT_DER: *format = tlv_format_der; return TLV_OK;
#endif
#if OPENTLV_FORMAT_CER
        case GO_FORMAT_CER: *format = tlv_format_cer; return TLV_OK;
#endif
#if OPENTLV_EMV
        case GO_FORMAT_EMV: *format = tlv_format_emv; return TLV_OK;
#endif
#if OPENTLV_LLDP
        case GO_FORMAT_LLDP: *format = tlv_format_lldp; return TLV_OK;
#endif
#if OPENTLV_BLUETOOTH
        case GO_FORMAT_BLUETOOTH_LTV: *format = tlv_format_bluetooth_ltv; return TLV_OK;
#endif
#if OPENTLV_DHCP
        case GO_FORMAT_DHCPV4: *format = tlv_format_dhcpv4; return TLV_OK;
#endif
#if OPENTLV_NFC
        case GO_FORMAT_NFC_TYPE2: *format = tlv_format_nfc_type2; return TLV_OK;
#endif
        default: return TLV_ERR_UNSUPPORTED_TYPE;
    }
}

tlv_result_t go_format_check(go_format config) {
    tlv_format_t       format;
    tlv_fixed_format_t fixed;
    return resolve(config, &format, &fixed);
}

go_read_result go_read(go_format config, const uint8_t* data, size_t size, int final_input) {
    go_read_result     result = {0};
    tlv_format_t       format;
    tlv_fixed_format_t fixed;
    tlv_reader_t       reader;
    tlv_reader_diagnostic_init(&result.diagnostic);
    result.code = resolve(config, &format, &fixed);
    if (result.code != TLV_OK) return result;
    result.code = final_input ? tlv_reader_init(&reader, data, size, &format)
                              : tlv_reader_init_incremental(&reader, data, size, &format);
    if (result.code != TLV_OK) return result;
    result.code =
        tlv_reader_next_source_diag(&reader, &result.element, &result.source, &result.diagnostic);
    if (result.code == TLV_OK) result.consumed = tlv_reader_consumed(&reader);
    /* The Go projection keeps ranges, never the temporary descriptor address. */
    result.source.format = NULL;
    return result;
}

go_write_result go_write(go_format config, uint8_t* data, size_t capacity, const uint8_t* tag,
                         size_t tag_size, const uint8_t* value, size_t value_size, int measure) {
    go_write_result    result = {0};
    tlv_format_t       format;
    tlv_fixed_format_t fixed;
    tlv_element_t      element;
    tlv_writer_diagnostic_init(&result.diagnostic);
    result.code = resolve(config, &format, &fixed);
    if (result.code != TLV_OK) return result;
    element.tag = tlv_tag(tag, tag_size);
    element.value.data = value;
    element.value.size = value_size;
    result.code =
        measure ? tlv_element_encoded_size_diag(&element, &format, &result.size, &result.diagnostic)
                : tlv_write_element_diag(data, capacity, &format, &element, &result.size,
                                         &result.diagnostic);
    return result;
}
