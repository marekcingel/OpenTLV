#ifndef OPENTLV_FUZZ_FORMATS_H
#define OPENTLV_FUZZ_FORMATS_H

#include "common.h"
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

/* Local, mutable copies of the formats without a built-in nesting rule, so
 * fuzz_constructed() can be attached to `is_constructed` without mutating the
 * library's own extern const globals. Populated by LLVMFuzzerInitialize()
 * below; tlv_fixed_format_t-based formats additionally need a runtime init
 * call and cannot be compile-time constants like the other entries here. */
#if OPENTLV_FORMAT_FIXED
static const tlv_fixed_format_t fuzz_fixed_config = {1, 1, TLV_BYTE_ORDER_BIG_ENDIAN,
                                                     TLV_ELEMENT_ORDER_TLV, TLV_LENGTH_SCOPE_VALUE};
static tlv_format_t             fuzz_fixed_format;
#endif
#if OPENTLV_FORMAT_BLUETOOTH_LTV
static tlv_format_t fuzz_bluetooth_ltv_format;
#endif

static const struct {
    const tlv_format_t* format;
} fuzz_formats[] = {
#if OPENTLV_FORMAT_FIXED
    {&fuzz_fixed_format},
#endif
#if OPENTLV_FORMAT_BLUETOOTH_LTV
    {&fuzz_bluetooth_ltv_format},
#endif
#if OPENTLV_FORMAT_BER
    {&tlv_format_ber},
#endif
#if OPENTLV_FORMAT_DER
    {&tlv_format_der},
#endif
    {NULL}};

/* libFuzzer calls this once before any input is fuzzed. */
int LLVMFuzzerInitialize(int* argc, char*** argv) {
    (void)argc;
    (void)argv;
#if OPENTLV_FORMAT_FIXED
    tlv_fixed_format_init(&fuzz_fixed_format, &fuzz_fixed_config);
    fuzz_fixed_format.is_constructed = fuzz_constructed;
#endif
#if OPENTLV_FORMAT_BLUETOOTH_LTV
    fuzz_bluetooth_ltv_format = tlv_format_bluetooth_ltv;
    fuzz_bluetooth_ltv_format.is_constructed = fuzz_constructed;
#endif
    return 0;
}

#endif
