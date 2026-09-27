#ifndef OPENTLV_FUZZ_FORMATS_H
#define OPENTLV_FUZZ_FORMATS_H

#include "common.h"
#if OPENTLV_FORMAT_DEFAULT
#include "tlv/builtins/fixed/default.h"
#endif
#if OPENTLV_FORMAT_FIXED
#include "tlv/formats/fixed.h"
#endif
#if OPENTLV_FORMAT_BLUETOOTH_LTV
#include "tlv/builtins/bluetooth/bluetooth_ltv.h"
#endif
#if OPENTLV_FORMAT_BER
#include "tlv/builtins/asn1/ber.h"
#endif
#if OPENTLV_FORMAT_DER
#include "tlv/builtins/asn1/der.h"
#endif

/* Raw-byte formats have no built-in nesting rule. This test convention lets
 * the walker exercise their nested values too: bit 0x20 denotes a container. */
static inline int fuzz_constructed(const void* context, const tlv_tag_t* tag) {
    (void)context;
    return (tag->data[0] & 0x20) != 0;
}

#if OPENTLV_FORMAT_FIXED
/* One tag byte and one length byte: populated by LLVMFuzzerInitialize()
 * below, since tlv_fixed_format_t-based formats need a runtime init call
 * and cannot be compile-time constants like the other entries here. */
static const tlv_fixed_format_t fuzz_fixed_config = {1, 1, TLV_BYTE_ORDER_BIG_ENDIAN};
static tlv_format_t             fuzz_fixed_format;
#endif

static const struct {
    const tlv_format_t*   format;
    tlv_is_constructed_fn constructed;
} fuzz_formats[] = {
#if OPENTLV_FORMAT_DEFAULT
    {&tlv_format_default, fuzz_constructed},
#endif
#if OPENTLV_FORMAT_FIXED
    {&fuzz_fixed_format, fuzz_constructed},
#endif
#if OPENTLV_FORMAT_BLUETOOTH_LTV
    {&tlv_format_bluetooth_ltv, fuzz_constructed},
#endif
#if OPENTLV_FORMAT_BER
    {&tlv_format_ber, tlv_ber_is_constructed},
#endif
#if OPENTLV_FORMAT_DER
    {&tlv_format_der, tlv_der_is_constructed},
#endif
    {NULL, NULL}};

/* libFuzzer calls this once before any input is fuzzed. */
int LLVMFuzzerInitialize(int* argc, char*** argv) {
    (void)argc;
    (void)argv;
#if OPENTLV_FORMAT_FIXED
    tlv_fixed_format_init(&fuzz_fixed_format, &fuzz_fixed_config);
#endif
    return 0;
}

#endif
