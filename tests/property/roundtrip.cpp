// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel
#include "tlv/config.h"
#include "tlv/formats/fixed.h"
#include "tlv/reader/tree.h"
#include "tlv/writer/tree.h"
#if OPENTLV_FORMAT_BER
#include "tlv/builtins/asn1/ber.h"
#endif
#if OPENTLV_FORMAT_DER
#include "tlv/builtins/asn1/der.h"
#endif
#if OPENTLV_EMV
#include "tlv/builtins/emv/format.h"
#endif
#if OPENTLV_BLUETOOTH
#include "tlv/builtins/bluetooth/bluetooth_ltv.h"
#endif
#if OPENTLV_NFC
#include "tlv/builtins/nfc/type2.h"
#endif
#include <cstring>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <vector>

int main(int argc, char** argv) try {
    // format input output max-depth max-elements tag-width length-width byte-order
    if (argc != 9) return 2;
    const size_t depth = std::stoul(argv[4]), elements = std::stoul(argv[5]);
    if (depth > 64 || !elements) return 2;
    const tlv_fixed_format_t fixed = {std::stoul(argv[6]), std::stoul(argv[7]),
                                      !std::strcmp(argv[8], "little") ? TLV_BYTE_ORDER_LITTLE_ENDIAN
                                                                      : TLV_BYTE_ORDER_BIG_ENDIAN,
                                      TLV_ELEMENT_ORDER_TLV, TLV_LENGTH_SCOPE_VALUE};
    tlv_format_t             descriptor{};
    const tlv_format_t*      format = nullptr;
    if (!std::strcmp(argv[1], "fixed")) {
        if (tlv_fixed_format_init(&descriptor, &fixed) != TLV_OK) return 2;
        format = &descriptor;
    }
#if OPENTLV_FORMAT_BER
    if (!std::strcmp(argv[1], "ber")) format = &tlv_format_ber;
#endif
#if OPENTLV_FORMAT_DER
    if (!std::strcmp(argv[1], "der")) format = &tlv_format_der;
#endif
#if OPENTLV_EMV
    if (!std::strcmp(argv[1], "emv")) format = &tlv_format_emv;
#endif
#if OPENTLV_BLUETOOTH
    if (!std::strcmp(argv[1], "bluetooth-ltv")) format = &tlv_format_bluetooth_ltv;
#endif
#if OPENTLV_NFC
    if (!std::strcmp(argv[1], "nfc-type2")) format = &tlv_format_nfc_type2;
#endif
    if (!format) return 2;
    std::ifstream source(argv[2], std::ios::binary);
    if (!source) return 2;
    const std::vector<uint8_t> input((std::istreambuf_iterator<char>(source)), {});
    if (source.bad() || input.empty()) return 2;
    // Extra headroom allows a changed encoding to be captured for comparison.
    if (input.size() > (SIZE_MAX - 1024) / 2) return 2;
    std::vector<uint8_t>                 output(input.size() * 2 + 1024), scratch(output.size());
    std::vector<tlv_tree_frame_t>        read_frames(depth + 1);
    std::vector<tlv_tree_writer_frame_t> write_frames(depth + 1);
    tlv_tree_reader_t                    reader{};
    tlv_tree_writer_t                    writer{};
    tlv_result_t rc = tlv_tree_reader_init(&reader, input.data(), input.size(), format,
                                           read_frames.data(), read_frames.size(), depth, elements);
    if (rc == TLV_OK)
        rc = tlv_tree_writer_init(&writer, output.data(), output.size(), format,
                                  write_frames.data(), write_frames.size(), scratch.data(),
                                  scratch.size(), depth, elements);
    while (rc == TLV_OK) {
        tlv_tree_event_t event{};
        rc = tlv_tree_reader_next_event(&reader, &event);
        if (rc == TLV_ERR_END_OF_BUFFER) {
            rc = tlv_tree_reader_at_end(&reader) ? tlv_tree_writer_finish(&writer)
                                                 : TLV_ERR_INVALID_ARG;
            break;
        }
        if (rc == TLV_OK) rc = tlv_tree_writer_write_event(&writer, &event);
    }
    const size_t  size = tlv_tree_writer_size(&writer);
    std::ofstream destination(argv[3], std::ios::binary);
    destination.write(reinterpret_cast<const char*>(output.data()),
                      static_cast<std::streamsize>(size));
    destination.close();
    if (!destination) return 2;
    if (rc != TLV_OK) {
        std::cerr << "Reader/Tree Writer error " << static_cast<int>(rc) << " at offset "
                  << tlv_tree_reader_offset(&reader) << '\n';
        return 1;
    }
    if (size != input.size() || std::memcmp(input.data(), output.data(), size)) {
        std::cerr << "byte-exact comparison failed: input=" << input.size() << " output=" << size
                  << '\n';
        return 1;
    }
    return 0;
} catch (const std::exception& error) {
    std::cerr << error.what() << '\n';
    return 2;
}
