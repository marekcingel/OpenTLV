#include "encode.hpp"
#include <cstring>
#include <cstdint>
#include <iostream>
#include <new>
#include <string>
#include "diagnostics.hpp"
#include "input.hpp"
#include "tlv/config.h"
#include "tlv/writer/writer.h"
#if OPENTLV_FORMAT_DEFAULT
#include "tlv/formats/default/default.h"
#endif
#if OPENTLV_FORMAT_FIXED_1BYTE
#include "tlv/formats/fixed/fixed_1byte.h"
#endif
#if OPENTLV_FORMAT_BER
#include "tlv/formats/asn1/ber.h"
#endif
#if OPENTLV_FORMAT_DER
#include "tlv/formats/asn1/der.h"
#endif
#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#endif

using cli::fail;

namespace {

const tlv_writer_format_t* select_writer(const char* name) {
#if OPENTLV_FORMAT_DEFAULT
    if (!strcmp(name, "default")) return &tlv_writer_format_default;
#endif
#if OPENTLV_FORMAT_FIXED_1BYTE
    if (!strcmp(name, "fixed-1byte")) return &tlv_writer_format_fixed_1byte;
#endif
#if OPENTLV_FORMAT_BER
    if (!strcmp(name, "ber")) return &tlv_writer_format_ber;
#endif
#if OPENTLV_FORMAT_DER
    if (!strcmp(name, "der")) return &tlv_writer_format_der;
#endif
    (void)name;
    return NULL;
}

// Builds the element list from --tag/--value.
int specs_from_options(const cli::options& o, std::vector<cli::commands::element_spec>& specs) {
    cli::commands::element_spec spec;
    int                         rc = cli::decode_hex(o.tag, TLV_TAG_CAPACITY, spec.tag);
    if (rc == 3) return fail(2, "tag is longer than the supported tag capacity");
    if (rc) return rc;
    if (spec.tag.empty()) return fail(2, "tag must not be empty");
    if (o.value && (rc = cli::decode_hex(o.value, o.max_input, spec.value))) return rc;
    specs.push_back(std::move(spec));
    return 0;
}

// Builds a tlv_tag_t from validated-length tag bytes (size <= TLV_TAG_CAPACITY).
tlv_tag_t make_tag(const std::vector<uint8_t>& bytes) {
    tlv_tag_t tag;
    std::memset(&tag, 0, sizeof tag);
    std::memcpy(tag.data, bytes.data(), bytes.size());
    tag.size = (uint8_t)bytes.size();
    return tag;
}

// Reports a writer rejection with the offending element's tag.
int write_failed(std::size_t index, tlv_result_t rc) {
    std::cerr << "otlv: cannot encode element " << index << ": " << tlv_strerror(rc) << "\n";
    return rc == TLV_ERR_OUT_OF_MEMORY ? 3 : 1;
}

} // namespace

namespace cli {
namespace commands {

int encode(const options& o) {
    const tlv_writer_format_t* format = select_writer(o.format);
    std::vector<element_spec>  specs;
    std::vector<uint8_t>       out;
    std::size_t                total = 0, i;
    int                        rc;

    if (!format) return fail(2, "unknown or disabled format; use otlv formats");
    if ((rc = specs_from_options(o, specs))) return rc;

    // Validate every element and size the whole output before writing, so a
    // rejected element never yields partial output.
    for (i = 0; i < specs.size(); ++i) {
        std::size_t  size;
        tlv_result_t result =
            tlv_encoded_size(make_tag(specs[i].tag), specs[i].value.size(), format, &size);
        if (result != TLV_OK) return write_failed(i, result);
        if (total > SIZE_MAX - size) return fail(3, "encoded output too large");
        total += size;
    }
    try {
        out.resize(total);
    } catch (const std::bad_alloc&) {
        return fail(3, "cannot allocate CLI memory");
    }
    tlv_writer_t writer;
    if (tlv_writer_init(&writer, out.data(), out.size(), format) != TLV_OK)
        return fail(3, "cannot initialize writer");
    for (i = 0; i < specs.size(); ++i) {
        tlv_result_t result = tlv_writer_write(&writer, make_tag(specs[i].tag),
                                               specs[i].value.data(), specs[i].value.size());
        if (result != TLV_OK) return write_failed(i, result);
    }

    if (o.binary_output) {
#ifdef _WIN32
        if (_setmode(_fileno(stdout), _O_BINARY) == -1)
            return fail(3, "cannot set binary stdout mode");
#endif
        std::cout.write(reinterpret_cast<const char*>(out.data()), (std::streamsize)out.size());
    } else {
        static const char digits[] = "0123456789ABCDEF";
        std::string       text;
        text.reserve(out.size() * 2 + 1);
        for (i = 0; i < out.size(); ++i) {
            text += digits[out[i] >> 4];
            text += digits[out[i] & 0xF];
        }
        std::cout << text << "\n";
    }
    return flush_stdout();
}

} // namespace commands
} // namespace cli
