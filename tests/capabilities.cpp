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
    tlv_fixed_format_t config = {};
    config.tag_size = 1;
    config.length_size = 1;
    config.length_order = TLV_BYTE_ORDER_BIG_ENDIAN;
    tlv_format_t format;
    if (tlv_fixed_format_init(&format, &config) != TLV_OK) return 1;
    const auto view = tlv::native::borrow_format(format);
    return &tlv::native::descriptor(view) == &format ? 0 : 1;
}
