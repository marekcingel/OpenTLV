// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel
#include "tlv++/tlv.hpp"
#include "tlv++/native.hpp"

#if !OPENTLV_READER && defined(OPENTLV_READER_H)
#error Unrelated C++ headers must not import Reader
#endif
#if !OPENTLV_WRITER && defined(OPENTLV_WRITER_H)
#error Unrelated C++ headers must not import Writer
#endif

int main() {
#if OPENTLV_QUERY && OPENTLV_READER && OPENTLV_QUERY_FRONTEND
    tlv::query_environment environment(tlv::fixed_format<1, 1>{});
    tlv::query_options     options(&environment);
    auto                   program = tlv::query_program::compile("count(//01)", options);
    if (!program || program->result_type() != tlv::query_type::integer) return 4;
#endif
#if OPENTLV_CODEC
    // Generic typed Value codecs remain usable without Schema or traversal.
    auto byte_value = tlv::uint8_codec::encode(uint8_t(1), nullptr, 0);
    if (!byte_value || *byte_value != 1) return 2;
#endif
#if OPENTLV_CODEC && OPENTLV_EMV && OPENTLV_SCHEMA
    // EMV dictionary codecs deliberately include the domain's Schema constraints.
    auto amount = tlv::emv::amount_codec::encode(uint64_t(1), nullptr, 0);
    if (!amount || *amount != 6) return 3;
#endif
    tlv_fixed_format_t config = {};
    config.identifier.size = 1;
    config.length.size = 1;
    config.length.byte_order = TLV_BYTE_ORDER_BIG_ENDIAN;
    tlv_format_t format;
    if (tlv_fixed_format_init(&format, &config) != TLV_OK) return 1;
    const auto view = tlv::native::borrow_format(format);
    return &tlv::native::descriptor(view) == &format ? 0 : 1;
}
